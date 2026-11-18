import { createClient } from "npm:@supabase/supabase-js@2";
import { createRemoteJWKSet, jwtVerify } from "npm:jose@5.9.6";

const FIREBASE_PROJECT_ID = "murmur-fc430";
const FIREBASE_JWKS = createRemoteJWKSet(new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"));

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
function reply(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: cors });
}
const makeDb = () => {
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) throw new Error("Server configuration is incomplete.");
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
};
async function rateLimit(db: ReturnType<typeof makeDb>, key: string, limit: number) {
  const { data, error } = await db.rpc("consume_edge_rate_limit", {
    p_key: key, p_limit: limit, p_window_seconds: 300,
  });
  if (error) throw error;
  return data === true;
}
async function audit(db: ReturnType<typeof makeDb>, adminId: string, action: string, targetUserId: string | null, reason = "", metadata = {}) {
  const { error } = await db.from("admin_audit_log").insert({
    admin_id: adminId, action, target_user_id: targetUserId, reason, metadata,
  });
  if (error) throw error;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return reply(405, { error: "Method not allowed." });
  try {
    const db = makeDb();
    const authorization = req.headers.get("Authorization") || "";
    const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    if (!token) return reply(401, { error: "Sign in with your Firebase administrator account." });

    let firebaseClaims: Record<string, unknown>;
    try {
      const verified = await jwtVerify(token, FIREBASE_JWKS, {
        issuer: "https://securetoken.google.com/" + FIREBASE_PROJECT_ID,
        audience: FIREBASE_PROJECT_ID,
      });
      firebaseClaims = verified.payload as Record<string, unknown>;
    } catch {
      return reply(401, { error: "Your Firebase session is invalid or expired." });
    }

    const firebaseUid = typeof firebaseClaims.sub === "string" ? firebaseClaims.sub : "";
    const email = typeof firebaseClaims.email === "string" ? firebaseClaims.email.trim().toLowerCase() : "";
    if (!firebaseUid || !email || firebaseClaims.email_verified !== true) {
      return reply(401, { error: "Use a verified Firebase administrator email address." });
    }

    const ip = (req.headers.get("x-forwarded-for") || "unknown").split(",")[0].trim().slice(0, 80);
    if (!await rateLimit(db, "murmur-admin-ip:" + ip, 100)) {
      return new Response(JSON.stringify({ error: "Too many requests. Try again in five minutes." }), {
        status: 429, headers: { ...cors, "Retry-After": "300" },
      });
    }

    // The allowlist row remains the server-side authority. The Firebase UID and
    // client-supplied role are never accepted as administrator authorization.
    const { data: admin, error: adminError } = await db.from("murmur_admin_allowlist")
      .select("user_id,email,role,enabled")
      .eq("email", email)
      .eq("enabled", true)
      .maybeSingle();
    if (adminError) throw adminError;
    if (!admin || String(admin.email || "").trim().toLowerCase() !== email) {
      return reply(403, { error: "This Firebase account is not authorized as a Murmur administrator." });
    }
    if (admin.role !== "super_admin") {
      return reply(403, { error: "Super Admin permission is required for this control panel." });
    }

    const user = { id: String(admin.user_id), email };
    if (!await rateLimit(db, "murmur-admin-user:" + firebaseUid, 60)) {
      return new Response(JSON.stringify({ error: "Too many requests. Try again in five minutes." }), {
        status: 429, headers: { ...cors, "Retry-After": "300" },
      });
    }

    const body = await req.json().catch(() => ({}));
    const action = typeof body.action === "string" ? body.action : "overview";

    if (action === "refresh") {
      const { data, error } = await db.rpc("consume_murmur_manual_refresh_for_user", {
        p_user_id: user.id,
      });
      if (error) throw error;
      return reply(200, data || { allowed: false, retry_after_seconds: 0 });
    }

    if (action === "overview") {
      const tables = ["posts", "messages", "reports", "comments", "stories", "reels", "account_appeals"];
      const counts = await Promise.all(tables.map(async (table) => {
        const { count, error } = await db.from(table).select("*", { count: "exact", head: true });
        if (error) throw error;
        return [table, count || 0] as const;
      }));
      const { data: identityLinks, error: identityError } = await db.rpc("admin_list_firebase_identity_links");
      if (identityError) throw identityError;
      const { count: profileCount, error: profileError } = await db.from("profiles").select("*", { count: "exact", head: true });
      if (profileError) throw profileError;
      return reply(200, {
        admin: { id: user.id, email: user.email, role: admin.role },
        counts: Object.fromEntries([["users", (identityLinks || []).length], ["profiles_ready", profileCount || 0], ...counts]),
      });
    }

    if (action === "identities") {
      const { data, error } = await db.rpc("admin_list_firebase_identity_links");
      if (error) throw error;
      return reply(200, {
        identities: (data || []).map((row: Record<string, unknown>) => ({
          firebase_uid: row.firebase_uid,
          supabase_id: row.supabase_id,
          linked_at: row.linked_at,
          username: row.username || null,
          display_name: row.display_name || null,
        })),
        total: (data || []).length,
      });
    }

    if (action === "users") {
      type AdminUserRow = {
        id: string;
        firebase_uid: string;
        username: string | null;
        display_name: string | null;
        created_at: string | null;
        is_suspended: boolean;
        suspension_reason: string | null;
        has_profile: boolean;
      };
      const page = Number.isInteger(body.page) ? Math.max(1, Math.min(body.page, 100000)) : 1;
      const pageSize = 50;
      const search = typeof body.q === "string" ? body.q.trim().slice(0, 80).toLowerCase() : "";
      const status = ["all", "active", "suspended"].includes(body.status) ? body.status : "all";
      const [{ data: identityLinks, error: identityError }, { data: profiles, error: profilesError }] = await Promise.all([
        db.rpc("admin_list_firebase_identity_links"),
        db.from("profiles").select("id,username,display_name,bio,avatar_url,created_at,is_suspended,suspension_reason"),
      ]);
      if (identityError) throw identityError;
      if (profilesError) throw profilesError;
      const profileById = new Map((profiles || []).map((profile) => [profile.id, profile]));
      let users: AdminUserRow[] = (identityLinks || []).map((link: Record<string, unknown>) => {
        const profile = profileById.get(link.supabase_id as string);
        return {
          id: String(link.supabase_id),
          firebase_uid: String(link.firebase_uid),
          username: (profile?.username ?? link.username ?? null) as string | null,
          display_name: (profile?.display_name ?? link.display_name ?? null) as string | null,
          created_at: (profile?.created_at ?? link.linked_at ?? null) as string | null,
          is_suspended: Boolean(profile?.is_suspended ?? false),
          suspension_reason: (profile?.suspension_reason ?? null) as string | null,
          has_profile: Boolean(profile),
        };
      });
      if (search) {
        users = users.filter((item) =>
          [item.id, item.firebase_uid, item.username, item.display_name]
            .some((value) => String(value ?? "").toLowerCase().includes(search))
        );
      }
      if (status === "active") users = users.filter((item) => item.has_profile && !item.is_suspended);
      if (status === "suspended") users = users.filter((item) => item.has_profile && item.is_suspended);
      users.sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
      const total = users.length;
      const from = (page - 1) * pageSize;
      return reply(200, { users: users.slice(from, from + pageSize), page, page_size: pageSize, total, total_pages: Math.max(1, Math.ceil(total / pageSize)) });
    }

    if (action === "set_user_status") {
      const userId = typeof body.user_id === "string" ? body.user_id : "";
      const suspended = body.suspended === true;
      const reason = typeof body.reason === "string" ? body.reason.trim().slice(0, 500) : "";
      const hours = body.duration_hours == null || body.duration_hours === "" ? null : Number(body.duration_hours);
      if (!userId || userId === user.id) return reply(400, { error: "Choose a valid user. You cannot suspend your own admin account." });
      if (suspended && !reason) return reply(400, { error: "A suspension reason is required." });
      if (suspended && hours !== null && (!Number.isFinite(hours) || hours <= 0 || hours > 8760)) {
        return reply(400, { error: "Suspension duration must be between 1 and 8760 hours, or blank for indefinite." });
      }
      const { data, error } = await db.rpc("admin_set_account_status", {
        p_admin_id: user.id, p_user_id: userId, p_suspended: suspended,
        p_reason: reason || null, p_duration_hours: suspended ? hours : null,
      });
      if (error) {
        if (error.code === "P0002") return reply(404, { error: "User profile not found." });
        if (error.code === "22023") return reply(400, { error: error.message });
        throw error;
      }
      return reply(200, { ok: true, user: data });
    }

    if (action === "schedule_delete") {
      const userId = typeof body.user_id === "string" ? body.user_id : "";
      const reason = typeof body.reason === "string" ? body.reason.trim().slice(0, 500) : "";
      const deleteAt = typeof body.delete_at === "string" ? new Date(body.delete_at) : null;
      if (!userId || userId === user.id) return reply(400, { error: "Choose a valid user." });
      if (!reason || !deleteAt || !Number.isFinite(deleteAt.getTime()) || deleteAt.getTime() <= Date.now()) {
        return reply(400, { error: "A reason and future deletion date are required." });
      }
      const { data, error } = await db.rpc("admin_schedule_account_deletion", {
        p_admin_id: user.id, p_user_id: userId, p_reason: reason, p_delete_at: deleteAt.toISOString(),
      });
      if (error) {
        if (error.code === "P0002") return reply(404, { error: "User profile not found." });
        if (error.code === "22023") return reply(400, { error: error.message });
        throw error;
      }
      return reply(200, data);
    }

    if (action === "reports") {
      const { data, error } = await db.from("reports")
        .select("id,reporter_id,reported_user_id,post_id,reason,details,status,created_at")
        .order("created_at", { ascending: false }).limit(200);
      if (error) throw error;
      return reply(200, { reports: data || [] });
    }

    if (action === "update_report") {
      const reportId = typeof body.report_id === "string" ? body.report_id : "";
      const status = typeof body.status === "string" ? body.status : "";
      if (!reportId || !["open", "reviewing", "resolved", "dismissed"].includes(status)) return reply(400, { error: "A valid report ID and status are required." });
      const { data, error } = await db.from("reports").update({ status }).eq("id", reportId).select("id,status").maybeSingle();
      if (error) throw error;
      if (!data) return reply(404, { error: "Report not found." });
      await audit(db, user.id, "update_report", null, "", { report_id: reportId, status });
      return reply(200, { ok: true, report: data });
    }

    if (action === "posts") {
      const { data, error } = await db.from("posts").select("id,author_id,content,visibility,media_url,media_type,created_at").order("created_at", { ascending: false }).limit(200);
      if (error) throw error;
      return reply(200, { posts: data || [] });
    }
    if (action === "delete_post") {
      const postId = typeof body.post_id === "string" ? body.post_id : "";
      if (!postId) return reply(400, { error: "A post ID is required." });
      const { error } = await db.from("posts").delete().eq("id", postId);
      if (error) throw error;
      await audit(db, user.id, "delete_post", null, "", { post_id: postId });
      return reply(200, { ok: true });
    }

    if (action === "appeals") {
      const { data, error } = await db.from("account_appeals").select("id,user_id,restriction_id,message,status,admin_response,created_at,reviewed_at").order("created_at", { ascending: false }).limit(200);
      if (error) throw error;
      return reply(200, { appeals: data || [] });
    }
    if (action === "update_appeal") {
      const appealId = typeof body.appeal_id === "string" ? body.appeal_id : "";
      const status = typeof body.status === "string" ? body.status : "";
      const response = typeof body.admin_response === "string" ? body.admin_response.trim().slice(0, 2000) : "";
      if (!appealId || !["reviewing", "approved", "rejected"].includes(status)) return reply(400, { error: "Choose a valid appeal status." });
      const { data, error } = await db.from("account_appeals").update({
        status, admin_response: response || null, reviewed_at: new Date().toISOString(),
      }).eq("id", appealId).select("id,status,admin_response").maybeSingle();
      if (error) throw error;
      if (!data) return reply(404, { error: "Appeal not found." });
      await audit(db, user.id, "review_appeal", null, response, { appeal_id: appealId, status });
      return reply(200, { ok: true, appeal: data });
    }

    if (action === "announcements") {
      const { data, error } = await db.from("announcements").select("id,title,body,kind,is_pinned,published_at,expires_at,created_at").order("created_at", { ascending: false }).limit(100);
      if (error) throw error;
      return reply(200, { announcements: data || [] });
    }
    if (action === "create_announcement") {
      const allowedTitles = ["Important Update", "New Feature", "Feature Update", "Maintenance Notice", "Service Update", "Security Notice", "Account Notice", "Community Guidelines", "Event Announcement", "General Announcement"];
      const title = typeof body.title === "string" ? body.title.trim() : "";
      const content = typeof body.body === "string" ? body.body.trim().slice(0, 5000) : "";
      const kind = ["info", "warning", "success", "urgent"].includes(body.kind) ? body.kind : "info";
      if (!allowedTitles.includes(title)) return reply(400, { error: "Choose one of the 10 approved announcement titles." });
      if (!content) return reply(400, { error: "Announcement information is required." });
      const { data, error } = await db.from("announcements").insert({
        title, body: content, kind, is_pinned: false, created_by: user.id,
      }).select().single();
      if (error) throw error;
      await audit(db, user.id, "create_announcement", null, title, { announcement_id: data.id });
      return reply(200, { announcement: data });
    }
    if (action === "delete_announcement") {
      const id = typeof body.announcement_id === "string" ? body.announcement_id : "";
      if (!id) return reply(400, { error: "An announcement ID is required." });
      const { error } = await db.from("announcements").delete().eq("id", id);
      if (error) throw error;
      await audit(db, user.id, "delete_announcement", null, "", { announcement_id: id });
      return reply(200, { ok: true });
    }

    if (action === "preview_email_campaign" || action === "send_email_campaign") {
      const subject = typeof body.subject === "string" ? body.subject.trim().slice(0, 180) : "";
      const message = typeof body.message === "string" ? body.message.trim().slice(0, 5000) : "";
      if (!subject || !message) return reply(400, { error: "An email subject and message are required." });
      const apiKey = Deno.env.get("RESEND_API_KEY") || "";
      const sender = Deno.env.get("RESEND_FROM_EMAIL") || "";
      if (action === "send_email_campaign" && (!apiKey || !sender)) {
        return reply(503, { error: "Email sending is not configured. Set RESEND_API_KEY and RESEND_FROM_EMAIL as Supabase Edge Function secrets." });
      }

      // This campaign tool is intentionally limited to essential service/product
      // announcements. Do not use it for promotions or marketing without consent.
      const recipients: string[] = [];
      for (let page = 1; page <= 100; page += 1) {
        const { data, error } = await db.auth.admin.listUsers({ page, perPage: 1000 });
        if (error) throw error;
        const rows = data.users || [];
        for (const account of rows) {
          if (account.email && account.email_confirmed_at && !account.banned_until) {
            recipients.push(account.email.trim().toLowerCase());
          }
        }
        if (rows.length < 1000 || recipients.length >= 100000) break;
      }
      const uniqueRecipients = [...new Set(recipients)];
      if (action === "preview_email_campaign") {
        return reply(200, {
          recipient_count: uniqueRecipients.length,
          sender_configured: Boolean(sender),
          campaign_type: "essential_service_announcement",
        });
      }

      const campaignId = typeof body.campaign_id === "string" ? body.campaign_id : "";
      if (!/^[a-f0-9-]{36}$/i.test(campaignId)) {
        return reply(400, { error: "A valid campaign ID is required. Preview the campaign again before sending." });
      }
      if (!uniqueRecipients.length) return reply(400, { error: "No verified recipient email addresses were found." });

      const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
      })[char]);
      const htmlMessage = escapeHtml(message).replace(/\r?\n/g, "<br>");
      let accepted = 0;
      let failedBatches = 0;
      const failures: string[] = [];
      for (let offset = 0; offset < uniqueRecipients.length; offset += 100) {
        const chunk = uniqueRecipients.slice(offset, offset + 100);
        const batch = chunk.map((to) => ({
          from: sender,
          to: [to],
          subject,
          text: message + "\n\nYou are receiving this because you have a Murmur account. This message is an essential service or product announcement.",
          html: "<div style=\"font-family:Arial,sans-serif;line-height:1.6;white-space:normal\">" +
            htmlMessage + "<hr><p style=\"color:#666;font-size:12px\">You are receiving this because you have a Murmur account. This message is an essential service or product announcement.</p></div>",
        }));
        const response = await fetch("https://api.resend.com/emails/batch", {
          method: "POST",
          headers: {
            "Authorization": "Bearer " + apiKey,
            "Content-Type": "application/json",
            "Idempotency-Key": "murmur-campaign-" + campaignId + "-" + Math.floor(offset / 100),
          },
          body: JSON.stringify(batch),
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) {
          failedBatches += 1;
          failures.push("Batch " + (Math.floor(offset / 100) + 1) + ": " +
            String(result.message || result.name || "Resend request failed").slice(0, 180));
        } else {
          accepted += Array.isArray(result.data) ? result.data.length : chunk.length;
        }
      }
      await audit(db, user.id, "send_email_campaign", null, subject, {
        campaign_id: campaignId, recipient_count: uniqueRecipients.length,
        accepted, failed_batches: failedBatches,
      });
      return reply(failedBatches ? 207 : 200, {
        campaign_id: campaignId, recipient_count: uniqueRecipients.length,
        accepted, failed_batches: failedBatches, failures,
        delivery_status: "provider_accepted_not_delivery_confirmed",
      });
    }

    if (action === "errors") {
      const { data, error, count } = await db.from("murmur_error_logs")
        .select("id,firebase_uid,kind,message,code,source,line,column_number,page,stack,fingerprint,created_at", { count: "exact" })
        .order("created_at", { ascending: false }).limit(200);
      if (error) throw error;
      return reply(200, { errors: data || [], total: count || 0 });
    }

    if (action === "system") {
      const tables = ["posts","comments","messages","reports","stories","reels","account_appeals"];
      const counts = await Promise.all(tables.map(async (table) => {
        const { count, error } = await db.from(table).select("*", { count: "exact", head: true });
        if (error) throw error;
        return [table, count || 0] as const;
      }));
      const { data: identityLinks, error: identityError } = await db.rpc("admin_list_firebase_identity_links");
      if (identityError) throw identityError;
      const { count: profileCount, error: profileError } = await db.from("profiles").select("*", { count: "exact", head: true });
      if (profileError) throw profileError;
      const [{ data: errors, error: errorsError }, { data: restrictions, error: restrictionsError }] = await Promise.all([
        db.from("murmur_error_logs").select("id,created_at,kind,message,code,source,line,page,fingerprint").order("created_at", { ascending: false }).limit(100),
        db.from("account_restrictions").select("id,user_id,status,reason_code,reason,starts_at,ends_at,scheduled_delete_at,created_at").in("status", ["suspended","scheduled_deletion"]).order("created_at", { ascending: false }).limit(100)
      ]);
      if (errorsError) throw errorsError;
      if (restrictionsError) throw restrictionsError;
      return reply(200, { counts: Object.fromEntries([["users", (identityLinks || []).length], ["profiles_ready", profileCount || 0], ...counts]), errors: errors || [], restrictions: restrictions || [] });
    }

    if (action === "activity") {
      const { data, error } = await db.from("admin_audit_log").select("id,admin_id,action,target_user_id,reason,metadata,created_at").order("created_at", { ascending: false }).limit(200);
      if (error) throw error;
      return reply(200, { activity: data || [] });
    }

    return reply(400, { error: "Unknown admin action." });
  } catch (error) {
    console.error("murmur-admin-supabase:", error);
    return reply(500, { error: "The admin request could not be completed." });
  }
});