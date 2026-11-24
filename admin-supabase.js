/* Murmur Admin — Supabase-only client.
   Authentication uses Supabase Auth. Every privileged read/write is performed
   by the murmur-admin-supabase Edge Function, which verifies the allowlist. */
(function () {
  "use strict";

  const SUPABASE_URL = "https://pkadftvqslkykehcqedj.supabase.co";
  const SUPABASE_KEY = "sb_publishable_etoHiUGbJ96MUPzJABL12A_UiTWVxok";
  const FUNCTION_URL = SUPABASE_URL + "/functions/v1/murmur-admin-supabase";
  const client = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
  });

  const gate = document.getElementById("gate");
  const form = document.getElementById("loginForm");
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("pass");
  const submitButton = document.getElementById("go");
  const errorBox = document.getElementById("err");
  const escapeHtml = (value) => String(value == null ? "" : value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
  const dateLabel = (value) => value ? new Date(value).toLocaleString() : "—";
  const RESTRICTION_REASONS = [
    { code: "spam", label: "Spam or fake engagement" },
    { code: "harassment", label: "Harassment or bullying" },
    { code: "hate_speech", label: "Hate speech or discriminatory content" },
    { code: "impersonation", label: "Impersonation" },
    { code: "fraud", label: "Scams or fraud" },
    { code: "sexual_content", label: "Sexual or explicit content" },
    { code: "violence", label: "Violence or threats" },
    { code: "child_safety", label: "Child safety concern" },
    { code: "repeated_violations", label: "Repeated policy violations" },
    { code: "other", label: "Other" }
  ];
  const RESTRICTION_POLICY = {
    spam: { hours: 24, deletionDays: 7, note: "Automated enforcement: spam or fake engagement." },
    harassment: { hours: 72, deletionDays: 14, note: "Automated enforcement: harassment or bullying." },
    hate_speech: { hours: 168, deletionDays: 30, note: "Automated enforcement: hate speech or discriminatory content." },
    impersonation: { hours: 168, deletionDays: 14, note: "Automated enforcement: impersonation." },
    fraud: { hours: 720, deletionDays: 7, note: "Automated enforcement: scams or fraud." },
    sexual_content: { hours: 168, deletionDays: 14, note: "Automated enforcement: prohibited sexual or explicit content." },
    violence: { hours: 720, deletionDays: 7, note: "Automated enforcement: violence or threats." },
    child_safety: { hours: 876000, deletionDays: 1, note: "Automated enforcement: child safety concern; immediate permanent restriction." },
    repeated_violations: { hours: 720, deletionDays: 7, note: "Automated enforcement: repeated policy violations." },
    other: { hours: 24, deletionDays: 30, note: "Automated enforcement: other policy violation." }
  };
  function askRestrictionReason(title) {
    const choices = RESTRICTION_REASONS.map((item, index) => (index + 1) + ". " + item.label).join("\n");
    const choice = prompt(title + "\n\n" + choices + "\n\nEnter a number from 1 to 10:", "1");
    if (choice === null) return null;
    const selected = RESTRICTION_REASONS[Number(choice.trim()) - 1];
    if (!selected) { notice("Choose one of the ten listed reasons."); return null; }
    const policy = RESTRICTION_POLICY[selected.code];
    return { reason_code: selected.code, reason: policy.note, duration_hours: policy.hours, delete_at: new Date(Date.now() + policy.deletionDays * 86400000).toISOString(), policy };
  }
  let adminSession = null;
  let activeTab = "overview";
  let usersPage = 1;
  let usersQuery = "";
  let usersStatus = "all";
  let loadId = 0;
  let visitorChannel = null;
  let visitorReloadTimer = null;
  let permissionRefreshTimer = null;
  let visitorRealtimeStatus = "connecting";

  function setError(message) {
    errorBox.textContent = message || "";
    errorBox.hidden = !message;
  }

  const READ_ACTIONS = new Set(["session", "admins", "overview", "users", "blocked_users", "moderation_cases", "reports", "posts", "appeals", "verified_requests", "announcements", "notifications", "visitor_analytics", "errors", "system", "activity"]);
  const responseCache = new Map();
  const pendingRequests = new Map();
  const CACHE_TTL_MS = 8000;

  function clearResponseCache() {
    responseCache.clear();
  }

  async function api(action, payload) {
    const cacheable = READ_ACTIONS.has(action);
    const cacheKey = action + ":" + JSON.stringify(payload || {});
    if (cacheable) {
      const cached = responseCache.get(cacheKey);
      if (cached && Date.now() - cached.time < CACHE_TTL_MS) return cached.value;
      if (pendingRequests.has(cacheKey)) return pendingRequests.get(cacheKey);
    }
    const request = (async () => {
      const { data: sessionData, error: sessionError } = await client.auth.getSession();
      if (sessionError || !sessionData.session) throw new Error("Your session expired. Sign in again.");
      const response = await fetch(FUNCTION_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": SUPABASE_KEY,
          "Authorization": "Bearer " + sessionData.session.access_token
        },
        body: JSON.stringify({ action, ...(payload || {}) })
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) {
        const failure = new Error(result.error || "Admin request failed (" + response.status + ").");
        failure.status = response.status;
        throw failure;
      }
      if (cacheable) responseCache.set(cacheKey, { time: Date.now(), value: result });
      else clearResponseCache();
      return result;
    })();
    if (cacheable) pendingRequests.set(cacheKey, request);
    try {
      return await request;
    } finally {
      if (cacheable && pendingRequests.get(cacheKey) === request) pendingRequests.delete(cacheKey);
    }
  }

  async function showShell() {
    try {
      adminSession = await api("session");
    } catch (error) {
      await client.auth.signOut().catch(() => {});
      gate.hidden = false;
      setError(error.message || "Your administrator access could not be verified.");
      return;
    }
    gate.hidden = true;
    let root = document.getElementById("supabaseAdmin");
    if (!root) {
      root = document.createElement("main");
      root.id = "supabaseAdmin";
      root.className = "sa-shell";
      document.body.appendChild(root);
    }
    root.innerHTML = `
      <div class="sa-wrap">
        <div class="sa-sticky"><header class="sa-head">
          <div class="sa-brand-wrap">
            <span class="sa-brand-mark" aria-hidden="true"><svg viewBox="0 0 64 64"><path fill="currentColor" d="M16 4h32a12 12 0 0 1 12 12v24a12 12 0 0 1-12 12H31L15 62V52a12 12 0 0 1-11-12V16A12 12 0 0 1 16 4z"/><g fill="#fff"><rect x="15" y="23" width="5" height="10" rx="2.5"/><rect x="24" y="16" width="5" height="24" rx="2.5"/><rect x="33" y="20" width="5" height="16" rx="2.5"/><rect x="42" y="24" width="5" height="8" rx="2.5"/></g></svg></span>
            <div><div class="sa-brand">murmur<span> / admin</span></div><div class="sa-muted" id="saIdentity">Secure administration workspace</div></div>
          </div>
          <div class="sa-actions"><span class="sa-role" id="saRoleBadge">ADMIN</span><button class="sa-btn" id="saTheme" type="button" aria-label="Toggle theme">Theme</button><button class="sa-btn" id="saRefresh" type="button">Refresh data</button><button class="sa-btn" id="saSignOut" type="button">Sign out</button></div>
        </header><nav class="sa-tabs" aria-label="Admin sections">
          <button class="sa-tab" data-tab="overview" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="5" rx="2"/><rect x="13" y="10" width="8" height="11" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/></svg></span>Overview</button>
          <button class="sa-tab" data-tab="users" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><circle cx="17" cy="9" r="2.6"/><path d="M17 14c2.8 0 4.7 1.8 4.7 4.5"/></svg></span>Users</button>
          <button class="sa-tab" data-tab="blocks" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m6 6 12 12"/></svg></span>Blocked users</button>\n          <button class="sa-tab" data-tab="moderation" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><path d="M12 3 3 7v5c0 5 4 8 9 9 5-1 9-4 9-9V7z"/><path d="m8 12 2.5 2.5L16 9"/></svg></span>Moderation</button>
          <button class="sa-tab" data-tab="identities" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="7" cy="12" r="3"/><circle cx="17" cy="12" r="3"/><path d="M10 12h4"/></svg></span>Account IDs</button>
          <button class="sa-tab" data-tab="reports" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg></span>Reports</button>
          <button class="sa-tab" data-tab="posts" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg></span>Posts</button>
          <button class="sa-tab" data-tab="appeals" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><path d="m12 3 8 9-8 9-8-9z"/><path d="M12 8v5m0 3h.01"/></svg></span>Appeals</button>
          <button class="sa-tab" data-tab="verified_requests" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><path d="m12 2 2.4 6.1L21 10l-6.6 1.9L12 18l-2.4-6.1L3 10l6.6-1.9L12 2Z"/></svg></span>Badge requests</button>
          <button class="sa-tab" data-tab="notifications" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/></svg></span>Notifications</button>
          <button class="sa-tab" data-tab="announcements" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><path d="m3 11 18-5v12L3 13z"/><path d="m7 14 2 7h5l-3-6"/></svg></span>Announcements</button>
          <button class="sa-tab" data-tab="errors" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><path d="M12 3 2.8 19h18.4L12 3Z"/><path d="M12 9v4m0 3h.01"/></svg></span>Errors</button>
          <button class="sa-tab" data-tab="system" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4M7 9h3m4 0h3m-10 4h10"/></svg></span>System</button>
          <button class="sa-tab" data-tab="visitors" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3"/><circle cx="17" cy="9" r="2.5"/><path d="M2.5 20c0-3.5 2.8-5.5 6.5-5.5s6.5 2 6.5 5.5M16 14c3 0 5.5 1.8 5.5 4.5"/></svg></span>Visitors</button>
          <button class="sa-tab" data-tab="activity" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span>Activity</button>
          <button class="sa-tab" data-tab="admins" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3"/><path d="M2 20c0-3.5 2.8-6 7-6s7 2.5 7 6M18 8v6m-3-3h6"/></svg></span>Admins</button>
        </nav></div>
        <div id="saNotice" class="sa-message" hidden role="status"></div>
        <section id="saContent" aria-live="polite"><div class="sa-empty">Loading secure dashboard…</div></section>
      </div>`;
    root.querySelectorAll("[data-tab]").forEach((button) => {
      const allowed = (adminSession.allowed_tabs || []).includes(button.dataset.tab);
      button.hidden = !allowed;
      if (!allowed && button.dataset.tab === activeTab) activeTab = "overview";
    });
    const roleBadge = root.querySelector("#saRoleBadge");
    if (roleBadge) roleBadge.textContent = (adminSession.admin.role_label || adminSession.admin.role).toUpperCase();
    root.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => {
      activeTab = button.dataset.tab;
      notice("");
      loadTab();
    }));
    root.querySelector("#saRefresh").addEventListener("click", refreshManually);
    root.querySelector("#saSignOut").addEventListener("click", signOut);
    root.querySelector("#saTheme").addEventListener("click", toggleTheme);
    loadTab();
    if (window.MurmurErrors) window.MurmurErrors.flush();
    if (adminSession.is_root && (adminSession.allowed_tabs || []).includes("visitors")) startVisitorLiveUpdates();
    if (permissionRefreshTimer) clearInterval(permissionRefreshTimer);
    permissionRefreshTimer = setInterval(() => refreshAdminPermissions(), 30000);
  }

  async function startVisitorLiveUpdates() {
    if (visitorChannel) return;
    const { data: sessionData, error: sessionError } = await client.auth.getSession();
    if (sessionError || !sessionData.session) return;
    await client.realtime.setAuth(sessionData.session.access_token);
    if (visitorChannel) return;
    visitorRealtimeStatus = "connecting";
    visitorChannel = client.channel("admin:visitors", { config: { private: true } })
      .on("broadcast", { event: "visitor-change" }, () => {
        if (activeTab !== "visitors") return;
        if (visitorReloadTimer) clearTimeout(visitorReloadTimer);
        visitorReloadTimer = setTimeout(() => {
          visitorReloadTimer = null;
          if (activeTab === "visitors") loadTab();
        }, 650);
      })
      .subscribe((status) => {
        visitorRealtimeStatus = status === "SUBSCRIBED" ? "live" :
          (status === "CHANNEL_ERROR" || status === "TIMED_OUT" || status === "CLOSED" ? "reconnecting" : "connecting");
        const statusNode = document.getElementById("saVisitorLiveStatus");
        if (statusNode) {
          statusNode.textContent = visitorRealtimeStatus === "live" ? "Live updates connected" :
            (visitorRealtimeStatus === "reconnecting" ? "Reconnecting live updates…" : "Connecting live updates…");
          statusNode.classList.toggle("is-live", visitorRealtimeStatus === "live");
        }
        if (status === "SUBSCRIBED" && activeTab === "visitors") loadTab();
      });
  }

  async function stopVisitorLiveUpdates() {
    if (visitorReloadTimer) { clearTimeout(visitorReloadTimer); visitorReloadTimer = null; }
    if (visitorChannel) {
      const channel = visitorChannel;
      visitorChannel = null;
      await client.removeChannel(channel);
    }
  }

  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("murmur-theme", next); } catch (_) {}
  }

  function notice(message) {
    const node = document.getElementById("saNotice");
    if (!node) return;
    node.textContent = message || "";
    node.hidden = !message;
  }

  function updateTabs() {
    document.querySelectorAll("[data-tab]").forEach((button) => {
      const active = button.dataset.tab === activeTab;
      button.setAttribute("aria-current", String(active));
      button.classList.toggle("is-active", active);
    });
  }

  async function refreshAdminPermissions() {
    try {
      clearResponseCache();
      const previousRole = adminSession && adminSession.admin && adminSession.admin.role;
      adminSession = await api("session");
      document.querySelectorAll("[data-tab]").forEach((button) => {
        button.hidden = !(adminSession.allowed_tabs || []).includes(button.dataset.tab);
      });
      const roleBadge = document.getElementById("saRoleBadge");
      if (roleBadge) roleBadge.textContent = (adminSession.admin.role_label || adminSession.admin.role).toUpperCase();
      if (!(adminSession.allowed_tabs || []).includes(activeTab)) activeTab = "overview";
      updateTabs();
      if (previousRole !== adminSession.admin.role || activeTab === "visitors" || !document.querySelector('[data-tab="' + CSS.escape(activeTab) + '"]')) loadTab();
    } catch (error) {
      if (error.status === 401 || error.status === 403) await signOut();
    }
  }

  async function loadTab() {
    const run = ++loadId;
    updateTabs();
    const host = document.getElementById("saContent");
    const content = document.createElement("div");
    host.innerHTML = '<div class="sa-empty">Loading…</div>';
    try {
      if (activeTab === "admins") {
        const data = await api("admins");
        const ADMIN_ROLE_OPTIONS = [{role:"super_admin",label:"Super Admin",stage:2},{role:"head_admin",label:"Head Admin",stage:3},{role:"senior_admin",label:"Senior Admin",stage:4},{role:"junior_admin",label:"Junior Admin",stage:5}];
        const roleOptions = ADMIN_ROLE_OPTIONS.map((role) => '<option value="' + role.role + '">' + role.label + ' · Stage ' + role.stage + '</option>').join("");
        content.innerHTML = '<section class="sa-panel"><h2>Administrator access</h2><p>Only the Super God Admin can appoint, promote, demote, or disable administrators. Access changes are enforced by the server on every request.</p><form id="saAdminAdd" class="sa-toolbar" style="margin-top:14px"><input class="sa-search" id="saAdminEmail" type="email" placeholder="Account email" required aria-label="Account email"><select class="sa-search" id="saAdminRole" aria-label="Administrator stage">' + roleOptions + '</select><input class="sa-search" id="saAdminPassword" type="password" minlength="12" maxlength="128" required autocomplete="new-password" placeholder="New password (12+ characters)" aria-label="New administrator password"><button class="sa-btn primary" id="saAdminCreate" type="button">Create admin account</button><button class="sa-btn" id="saAdminAppoint" type="button">Appoint existing account</button></form><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Administrator</th><th>Stage</th><th>Status</th><th>Change access</th></tr></thead><tbody>' +
        (data.admins || []).map((item) => '<tr><td><strong>' + escapeHtml(item.email) + '</strong><div class="sa-muted">' + escapeHtml(item.user_id) + '</div></td><td>' + escapeHtml(item.role.replace(/_/g, " ")) + '</td><td><span class="sa-status">' + (item.enabled ? "Enabled" : "Disabled") + '</span></td><td>' + (item.user_id === adminSession.admin.id ? '<span class="sa-muted">Your root account is protected</span>' : '<div class="sa-cell-actions"><select class="sa-search sa-admin-role" data-admin-email="' + escapeHtml(item.email) + '" aria-label="Change stage for ' + escapeHtml(item.email) + '">' + roleOptions.replace('value="' + escapeHtml(item.role) + '"', 'value="' + escapeHtml(item.role) + '" selected') + '</select><button class="sa-btn primary sa-small" data-admin-save="' + escapeHtml(item.email) + '">Save</button><button class="sa-btn danger sa-small" data-admin-enabled="' + escapeHtml(item.email) + '" data-enabled="' + String(item.enabled) + '">' + (item.enabled ? "Disable" : "Enable") + '</button></div>') + '</td></tr>').join("") +
        '</tbody></table></div></section>';
        const adminForm = content.querySelector("#saAdminAdd");
        const createButton = content.querySelector("#saAdminCreate");
        const appointButton = content.querySelector("#saAdminAppoint");
        adminForm.addEventListener("submit", (event) => event.preventDefault());
        createButton.addEventListener("click", async () => {
          const email = content.querySelector("#saAdminEmail").value.trim().toLowerCase();
          const role = content.querySelector("#saAdminRole").value;
          const passwordInput = content.querySelector("#saAdminPassword");
          const password = passwordInput.value;
          if (!email || !password || password.length < 12) {
            notice("Enter a valid email and a new password with at least 12 characters.");
            return;
          }
          if (!confirm("Create a new Supabase login and assign " + role.replace(/_/g, " ") + " access to " + email + "?")) return;
          createButton.disabled = true;
          appointButton.disabled = true;
          createButton.textContent = "Creating account…";
          notice("Sending account creation request to Supabase…");
          try {
            const result = await api("create_admin", { email, role, password });
            passwordInput.value = "";
            clearResponseCache();
            notice(result.requires_email_confirmation
              ? "Account created successfully. The administrator must confirm the email before signing in."
              : "Administrator account created successfully.");
            await loadTab();
          } catch (error) {
            notice(error.message || "Could not create the administrator account. Check the email and try again.");
          } finally {
            createButton.disabled = false;
            appointButton.disabled = false;
            createButton.textContent = "Create admin account";
          }
        });
        appointButton.addEventListener("click", async () => {
          const email = content.querySelector("#saAdminEmail").value.trim().toLowerCase();
          const role = content.querySelector("#saAdminRole").value;
          if (!email) { notice("Enter the email of an existing Supabase account."); return; }
          await actionRun(() => api("set_admin_role", { email, role, enabled: true }), "Administrator appointed with the selected stage.");
        });
        content.querySelectorAll("[data-admin-save]").forEach((button) => button.addEventListener("click", async () => {
          const email = button.dataset.adminSave;
          const role = content.querySelector('[data-admin-email="' + CSS.escape(email) + '"]').value;
          await actionRun(() => api("set_admin_role", { email, role, enabled: true }), "Administrator stage updated. Their access has changed immediately.");
        }));
        content.querySelectorAll("[data-admin-enabled]").forEach((button) => button.addEventListener("click", async () => {
          const enabled = button.dataset.enabled !== "true";
          if (!confirm((enabled ? "Enable" : "Disable") + " administrator access for " + button.dataset.adminEnabled + "?")) return;
          const current = (data.admins || []).find((item) => item.email === button.dataset.adminEnabled);
          if (!current) return;
          await actionRun(() => api("set_admin_role", { email: current.email, role: current.role, enabled }), enabled ? "Administrator enabled." : "Administrator disabled.");
        }));
      } else if (activeTab === "overview") {
        const data = await api("overview");
        document.getElementById("saIdentity").textContent = data.admin.email + " · " + (adminSession.admin.role_label || data.admin.role);
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">CONTROL CENTER</span><h1>Overview</h1><p>Monitor your Murmur community and system activity.</p></div><span class="sa-live"><i></i> Connected session</span></div><div class="sa-grid">' + Object.entries(data.counts).map(([name, count]) =>
          '<article class="sa-card"><div class="sa-card-top"><span class="sa-muted">' + escapeHtml(name.replace(/_/g, " ")) +
          '</span><span class="sa-card-dot"></span></div><div class="sa-number">' + Number(count).toLocaleString() + '</div><div class="sa-card-foot">Current records</div></article>'
        ).join("") + '</div><section class="sa-panel sa-security-panel"><div class="sa-security-mark"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5 9-10"/></svg></div><div><h2>Administration protected</h2><p>Supabase Auth is active. Every section and action is checked against your current administrator stage on the server.</p></div></section>';
      } else if (activeTab === "users") {
        const data = await api("users", { page: usersPage, q: usersQuery, status: usersStatus });
        content.innerHTML = '<section class="sa-panel"><div class="sa-toolbar"><h2>Users</h2><form id="saUserSearch" class="sa-actions"><input class="sa-search" id="saSearch" type="search" value="' + escapeHtml(usersQuery) + '" placeholder="Search username, name, email or ID" aria-label="Search users"><select class="sa-search" id="saUserStatus" aria-label="Filter account status"><option value="all">All accounts</option><option value="active">Active</option><option value="suspended">Suspended</option></select><button class="sa-btn primary" type="submit">Search</button></form></div><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Account / username</th><th>Created</th><th>Status</th><th>Action</th></tr></thead><tbody>' +
          (data.users || []).map((user) => '<tr data-user-row="' + escapeHtml(user.id) + '"><td><strong>' + (user.username ? "@" + escapeHtml(user.username) : "Username not set") + '</strong><div class="sa-muted">' + escapeHtml(user.display_name || "Unnamed account") + '</div><div class="sa-muted">Email: ' + escapeHtml(user.email || "Not available") + '</div><div class="sa-muted">Supabase ID: ' + escapeHtml(user.id) + '</div><div class="sa-muted">Murmur ID: ' + escapeHtml(user.public_id || "—") + '</div>' + (user.is_verified ? '<span class="sa-status" style="margin-top:5px;display:inline-flex">Verified by Murmur</span>' : '') + '</td><td>' + escapeHtml(dateLabel(user.created_at)) + '</td><td><span class="sa-status">' + (user.is_terminated ? "Terminated" : (user.is_banned ? "Banned" : (user.is_suspended ? "Suspended" : "Active"))) + '</span>' + (user.suspension_reason ? '<div class="sa-muted">' + escapeHtml(user.suspension_reason) + '</div>' : '') + '</td><td><div class="sa-cell-actions">' +
          (user.is_terminated ? '<span class="sa-muted">Permanently disabled</span>' : ((user.is_verified ? '<button class="sa-btn sa-small" data-unverify="' + escapeHtml(user.id) + '">Remove verified badge</button>' : '<button class="sa-btn primary sa-small" data-verify="' + escapeHtml(user.id) + '">Give verified badge</button>') + (user.is_suspended ? '<button class="sa-btn sa-small" data-unsuspend="' + escapeHtml(user.id) + '">Restore</button>' : '<button class="sa-btn danger sa-small" data-suspend="' + escapeHtml(user.id) + '">Suspend</button>') + (user.is_banned ? '<button class="sa-btn sa-small" data-unban="' + escapeHtml(user.id) + '">Unban</button>' : '<button class="sa-btn danger sa-small" data-ban="' + escapeHtml(user.id) + '">Ban</button>') + '<button class="sa-btn sa-small" data-warning="' + escapeHtml(user.id) + '">Warning</button><button class="sa-btn sa-small" data-mute="' + escapeHtml(user.id) + '">Mute</button><button class="sa-btn danger sa-small" data-schedule-delete="' + escapeHtml(user.id) + '">Schedule deletion</button><button class="sa-btn danger sa-small" data-terminate-user="' + escapeHtml(user.id) + '">Terminate account</button>')) +
          '</div></td></tr>').join("") + '</tbody></table></div></section>';
        content.innerHTML += '<div class="sa-toolbar" style="justify-content:flex-end;align-items:center;margin-top:12px"><span class="sa-muted">Page ' + data.page + ' of ' + data.total_pages + ' · ' + Number(data.total).toLocaleString() + ' accounts</span><button class="sa-btn sa-small" id="saUsersPrev" type="button"' + (data.page <= 1 ? ' disabled' : '') + '>Previous</button><button class="sa-btn sa-small" id="saUsersNext" type="button"' + (data.page >= data.total_pages ? ' disabled' : '') + '>Next</button></div>';
        content.querySelector("#saUserStatus").value = usersStatus;
        content.querySelector("#saUserSearch").addEventListener("submit", (event) => {
          event.preventDefault();
          usersQuery = content.querySelector("#saSearch").value.trim();
          usersStatus = content.querySelector("#saUserStatus").value;
          usersPage = 1;
          loadTab();
        });
        content.querySelector("#saUserStatus").addEventListener("change", () => {
          usersStatus = content.querySelector("#saUserStatus").value;
          usersQuery = content.querySelector("#saSearch").value.trim();
          usersPage = 1;
          loadTab();
        });
        content.querySelector("#saUsersPrev").addEventListener("click", () => { if (usersPage > 1) { usersPage -= 1; loadTab(); } });
        content.querySelector("#saUsersNext").addEventListener("click", () => { if (usersPage < data.total_pages) { usersPage += 1; loadTab(); } });
        content.querySelectorAll("[data-verify]").forEach((button) => button.addEventListener("click", async () => {
          if (!confirm("Give this account the official Verified by Murmur badge? It will appear beside the user's name in Murmur.")) return;
          await actionRun(() => api("set_user_verified", { user_id: button.dataset.verify, verified: true }), "Verified badge granted.");
        }));
        content.querySelectorAll("[data-unverify]").forEach((button) => button.addEventListener("click", async () => {
          if (!confirm("Remove this account's Murmur verified badge?")) return;
          await actionRun(() => api("set_user_verified", { user_id: button.dataset.unverify, verified: false }), "Verified badge removed.");
        }));
        content.querySelectorAll("[data-suspend]").forEach((button) => button.addEventListener("click", async () => {
          const reason = askRestrictionReason("Choose the reason for suspending this account:");
          if (!reason) return;
          await actionRun(() => api("moderate_user", {
            user_id: button.dataset.suspend, type: "suspension",
            reason: reason.reason, reason_code: reason.reason_code,
            duration_hours: Math.min(reason.duration_hours, 8760), appealable: true
          }), "Account suspended. The system generated the notice and expiry automatically.");
        }));
        content.querySelectorAll("[data-ban]").forEach((button) => button.addEventListener("click", async () => {
          const reason = askRestrictionReason("Choose the reason for banning this account:");
          if (!reason) return;
          await actionRun(() => api("moderate_user", { user_id: button.dataset.ban, type: "ban", duration_hours: reason.duration_hours, reason: reason.reason, reason_code: reason.reason_code, appealable: true }), "Account banned. The system generated the notice and expiry automatically.");
        }));
        content.querySelectorAll("[data-unban]").forEach((button) => button.addEventListener("click", async () => {
          if (!confirm("Remove the ban from this account?")) return;
          await actionRun(() => api("unban_user", { user_id: button.dataset.unban }), "Account ban removed.");
        }));
        content.querySelectorAll("[data-terminate-user]").forEach((button) => button.addEventListener("click", async () => {
          const reason = askRestrictionReason("Choose the reason for permanently terminating this account:");
          if (!reason) return;
          if (!confirm("Permanently terminate this account for: " + reason.reason + "? Sign-in will be disabled immediately. Account records will be retained in the database for audit.")) return;
          await actionRun(() => api("moderate_user", { user_id: button.dataset.terminateUser, type: "termination", reason: reason.reason, reason_code: reason.reason_code, appealable: false }), "Account terminated. The reason and account status are saved in the database; sign-in is disabled.");
        }));
        content.querySelectorAll("[data-unsuspend]").forEach((button) => button.addEventListener("click", async () => {
          await actionRun(() => api("set_user_status", { user_id: button.dataset.unsuspend, suspended: false }), "Account restored.");
        }));
        content.querySelectorAll("[data-schedule-delete]").forEach((button) => button.addEventListener("click", async () => {
          const reason = askRestrictionReason("Choose the reason for scheduling account deletion:");
          if (!reason) return;
          const date = new Date(reason.delete_at);
          if (!confirm("Schedule account deletion for " + date.toLocaleString() + "? The system selected this date based on the reason. The account is suspended immediately.")) return;
          await actionRun(() => api("schedule_delete", {
            user_id: button.dataset.scheduleDelete, reason: reason.reason,
            reason_code: reason.reason_code, delete_at: date.toISOString()
          }), "Deletion scheduled. The system generated the note and date automatically.");
        }));
        content.querySelectorAll("[data-warning]").forEach(button => button.addEventListener("click", async () => {
          const reason = askRestrictionReason("Choose the reason for issuing a warning:");
          if (!reason) return;
          await actionRun(() => api("moderate_user", {
            user_id: button.dataset.warning, type: "warning", reason: reason.reason,
            reason_code: reason.reason_code, appealable: true
          }), "Warning issued and saved as a moderation case.");
        }));
        content.querySelectorAll("[data-mute]").forEach(button => button.addEventListener("click", async () => {
          const reason = askRestrictionReason("Choose the reason for muting this account:");
          if (!reason) return;
          await actionRun(() => api("moderate_user", {
            user_id: button.dataset.mute, type: "mute", reason: reason.reason,
            reason_code: reason.reason_code, duration_hours: reason.duration_hours, appealable: true
          }), "Mute issued and saved as a moderation case.");
        }));
      } else if (activeTab === "blocks") {
        const data = await api("blocked_users");
        const rows = data.blocks || [];
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">SAFETY & MODERATION</span><h1>Blocked users</h1><p>Review user-to-user blocks. Removing a block restores the ability to find or contact one another where other privacy rules allow.</p></div></div>' +
          '<section class="sa-panel"><div class="sa-toolbar"><h2>Active blocks (' + rows.length + ')</h2><span class="sa-muted">Private admin view</span></div><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Blocked by</th><th>Blocked account</th><th>Date</th><th>Action</th></tr></thead><tbody>' +
          (rows.length ? rows.map(item => '<tr><td><strong>' + escapeHtml(item.blocker?.username ? '@' + item.blocker.username : item.blocker?.display_name || item.blocker_id) + '</strong><div class="sa-muted">' + escapeHtml(item.blocker_id) + '</div></td><td><strong>' + escapeHtml(item.blocked?.username ? '@' + item.blocked.username : item.blocked?.display_name || item.blocked_id) + '</strong><div class="sa-muted">' + escapeHtml(item.blocked_id) + '</div></td><td>' + escapeHtml(dateLabel(item.created_at)) + '</td><td><button class="sa-btn danger sa-small" data-remove-block="' + escapeHtml(item.blocker_id) + '" data-blocked-id="' + escapeHtml(item.blocked_id) + '">Remove block</button></td></tr>').join('') : '<tr><td colspan="4">No active blocks found.</td></tr>') +
          '</tbody></table></div></section>';
        content.querySelectorAll("[data-remove-block]").forEach(button => button.addEventListener("click", async () => {
          if (!confirm("Remove this block? This does not recreate a friendship or restore a conversation automatically.")) return;
          await actionRun(() => api("remove_block", { blocker_id: button.dataset.removeBlock, blocked_id: button.dataset.blockedId }), "Block removed.");
        }));
      } else if (activeTab === "identities") {
        const data = await api("users", { page: 1, status: "all" });
        const accounts = data.users || [];
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">PRIVATE ADMIN VIEW</span><h1>Murmur account IDs</h1><p>Each account has a Supabase UUID and a separate 16-character Murmur public ID. Only authorized administrators can view both.</p></div><span class="sa-live"><i></i> Admin only</span></div>' +
          '<section class="sa-panel"><div class="sa-toolbar"><h2>Accounts (' + Number(data.total || accounts.length).toLocaleString() + ')</h2><span class="sa-muted">Showing the latest ' + accounts.length + ' accounts</span></div>' +
          '<div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Murmur public ID</th><th>Supabase UUID</th><th>Username</th><th>Name</th><th>Created</th></tr></thead><tbody>' +
          (accounts.length ? accounts.map((item) => '<tr><td><code>' + escapeHtml(item.public_id || "—") + '</code></td><td><code>' + escapeHtml(item.id) + '</code></td><td>' + escapeHtml(item.username || "—") + '</td><td>' + escapeHtml(item.display_name || "Unnamed account") + '</td><td>' + escapeHtml(dateLabel(item.created_at)) + '</td></tr>').join("") :
          '<tr><td colspan="5">No Supabase accounts have been created yet.</td></tr>') +
          '</tbody></table></div></section>';
      } else if (activeTab === "reports") {
        const data = await api("reports");
        content.innerHTML = '<section class="sa-panel"><h2>Reports</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Reason / details</th><th>Reported user</th><th>Date</th><th>Status</th><th>Action</th></tr></thead><tbody>' +
          (data.reports || []).map((report) => '<tr><td><strong>' + escapeHtml(report.reason || "No reason") + '</strong><div class="sa-muted">' + escapeHtml(report.details || "") + '</div><div class="sa-muted">Report ' + escapeHtml(report.id) + '</div></td><td>' + escapeHtml(report.reported_user_id || "—") + '</td><td>' + escapeHtml(dateLabel(report.created_at)) + '</td><td><span class="sa-status">' + escapeHtml(report.status || "open") + '</span></td><td><select class="sa-search sa-small" data-report-status="' + escapeHtml(report.id) + '"><option value="open">Open</option><option value="reviewing">Reviewing</option><option value="resolved">Resolved</option><option value="dismissed">Dismissed</option></select></td></tr>').join("") + '</tbody></table></div></section>';
        content.querySelectorAll("[data-report-status]").forEach((select) => {
          const report = data.reports.find((item) => item.id === select.dataset.reportStatus);
          select.value = report?.status || "open";
          select.addEventListener("change", async () => actionRun(() => api("update_report", { report_id: select.dataset.reportStatus, status: select.value }), "Report status updated."));
        });
      } else if (activeTab === "posts") {
        const data = await api("posts");
        content.innerHTML = '<section class="sa-panel"><h2>Posts</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Post</th><th>Author</th><th>Visibility</th><th>Created</th><th>Action</th></tr></thead><tbody>' +
          (data.posts || []).map((post) => '<tr><td>' + escapeHtml(post.content || (post.media_type || "Media post")) + '<div class="sa-muted">' + escapeHtml(post.id) + '</div></td><td>' + escapeHtml(post.author_id) + '</td><td>' + escapeHtml(post.visibility || "—") + '</td><td>' + escapeHtml(dateLabel(post.created_at)) + '</td><td><button class="sa-btn danger sa-small" data-delete-post="' + escapeHtml(post.id) + '">Delete</button></td></tr>').join("") + '</tbody></table></div></section>';
        content.querySelectorAll("[data-delete-post]").forEach((button) => button.addEventListener("click", (event) => {
          event.preventDefault();
          content.querySelector("#saPostRemovalReason")?.remove();
          const reasons = [
            ["spam", "Spam or misleading content"],
            ["harassment", "Harassment or bullying"],
            ["hate_speech", "Hateful or discriminatory content"],
            ["impersonation", "Impersonation"],
            ["fraud", "Fraud or scams"],
            ["sexual_content", "Sexual or explicit content"],
            ["violence", "Violence or threats"],
            ["child_safety", "Child safety concern"],
            ["copyright", "Copyright or intellectual property violation"],
            ["other", "Other Community Guidelines violation"]
          ];
          const panel = document.createElement("section");
          panel.id = "saPostRemovalReason";
          panel.className = "sa-panel";
          panel.style.cssText = "margin:16px 0;padding:20px;border:2px solid var(--sa-accent,#64748b);border-radius:14px;background:var(--sa-card,#fff);color:var(--sa-text,#111);";
          panel.innerHTML = '<h2 style="margin:0 0 8px">Choose one of the approved post-removal reasons</h2><p class="sa-muted" style="margin:0 0 14px">Select the reason Murmur will send to the post author. The notification text is generated automatically and cannot be edited.</p><label for="saPostRemovalReasonSelect" style="display:block;font-weight:600;margin-bottom:8px">Post removal reason</label><select id="saPostRemovalReasonSelect" class="sa-search" style="display:block;width:100%;max-width:none;margin:0 0 14px;padding:12px;min-height:46px"><option value="">Select an approved reason…</option>' +
            reasons.map((item) => '<option value="' + item[0] + '">' + escapeHtml(item[1]) + '</option>').join("") +
            '</select><div class="sa-actions"><button class="sa-btn primary" type="button" id="saConfirmPostRemoval">Continue</button><button class="sa-btn" type="button" id="saCancelPostRemoval">Cancel</button></div>';
          host.prepend(panel);
          panel.scrollIntoView({ behavior: "smooth", block: "center" });
          panel.querySelector("#saPostRemovalReasonSelect").focus();
          panel.querySelector("#saCancelPostRemoval").addEventListener("click", () => { panel.remove(); button.disabled = false; });
          panel.querySelector("#saConfirmPostRemoval").addEventListener("click", async () => {
            const code = panel.querySelector("#saPostRemovalReasonSelect").value;
            const selected = reasons.find((item) => item[0] === code);
            if (!selected) {
              notice("Choose one of the approved post-removal reasons.");
              panel.querySelector("#saPostRemovalReasonSelect").focus();
              return;
            }
            if (!confirm("Delete this post and send the fixed removal notification to its author?\nReason: " + selected[1])) return;
            const confirmButton = panel.querySelector("#saConfirmPostRemoval");
            confirmButton.disabled = true;
            confirmButton.textContent = "Deleting…";
            try {
              const result = await api("delete_post", {
                post_id: button.dataset.deletePost,
                reason_code: code
              });
              if (!result || result.ok !== true) {
                throw new Error("The server did not confirm that the post was deleted.");
              }
              panel.remove();
              button.closest("tr")?.remove();
              notice("Post deleted and the author was notified.");
              await loadTab();
            } catch (error) {
              confirmButton.disabled = false;
              confirmButton.textContent = "Continue";
              button.disabled = false;
              notice(error.message || "Post deletion failed.");
            }
          });
        }));
      } else if (activeTab === "moderation") {
        const data = await api("moderation_cases");
        const cases = data.cases || [];
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">TRUST & SAFETY</span><h1>Moderation cases</h1><p>Review warnings, mutes, suspensions, bans and terminations.</p></div></div><section class="sa-panel"><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Case ID / account</th><th>Action</th><th>Reason</th><th>Issued</th><th>Expiry</th><th>Status</th><th></th></tr></thead><tbody>' +
          (cases.length ? cases.map(item => '<tr><td><strong>' + escapeHtml(item.id) + '</strong><div class="sa-muted">' + escapeHtml(item.profile?.username ? '@' + item.profile.username : item.profile?.display_name || item.user_id) + '</div><div class="sa-muted">' + escapeHtml(item.user_id) + '</div></td><td><span class="sa-status">' + escapeHtml(item.type) + '</span></td><td>' + escapeHtml(item.reason) + '</td><td>' + escapeHtml(dateLabel(item.created_at)) + '</td><td>' + escapeHtml(dateLabel(item.expires_at)) + '</td><td>' + (item.revoked_at ? 'Lifted' : (item.expires_at && new Date(item.expires_at).getTime() <= Date.now() ? 'Expired' : 'Active')) + '</td><td>' + (!item.revoked_at && (!item.expires_at || new Date(item.expires_at).getTime() > Date.now()) ? '<button class="sa-btn sa-small" data-lift-case="' + escapeHtml(item.id) + '">Lift action</button>' : '—') + '</td></tr>').join('') : '<tr><td colspan="7">No moderation cases yet.</td></tr>') +
          '</tbody></table></div></section>';
        content.querySelectorAll("[data-lift-case]").forEach(button => button.addEventListener("click", async () => {
          if (!confirm("Lift this moderation action? The account will be restored only if no other active restriction remains.")) return;
          await actionRun(() => api("lift_moderation_case", { case_id: button.dataset.liftCase }), "Moderation action lifted.");
        }));
      } else if (activeTab === "appeals") {
        const data = await api("appeals");
        const moderationAppeals = data.moderation_appeals || [];
        content.innerHTML = '<section class="sa-panel"><h2>Account appeals</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Appeal / case</th><th>Account</th><th>Submitted</th><th>Status</th><th>Review</th></tr></thead><tbody>' +
          (data.appeals || []).map((appeal) => '<tr><td>' + escapeHtml(appeal.message) + '<div class="sa-muted">' + escapeHtml(appeal.id) + '</div></td><td>' + escapeHtml(appeal.user_id) + '</td><td>' + escapeHtml(dateLabel(appeal.created_at)) + '</td><td><span class="sa-status">' + escapeHtml(appeal.status) + '</span></td><td><button class="sa-btn sa-small" data-review-appeal="' + escapeHtml(appeal.id) + '" data-status="reviewing">Review</button> <button class="sa-btn sa-small" data-review-appeal="' + escapeHtml(appeal.id) + '" data-status="approved">Approve</button> <button class="sa-btn danger sa-small" data-review-appeal="' + escapeHtml(appeal.id) + '" data-status="rejected">Reject</button></td></tr>').join("") +
          moderationAppeals.map(appeal => '<tr><td>' + escapeHtml(appeal.message) + '<div class="sa-muted">Case: ' + escapeHtml(appeal.action_id) + '</div><div class="sa-muted">' + escapeHtml(appeal.id) + '</div></td><td>' + escapeHtml(appeal.user_id) + '</td><td>' + escapeHtml(dateLabel(appeal.created_at)) + '</td><td><span class="sa-status">' + escapeHtml(appeal.status) + '</span></td><td>' + (appeal.status === 'pending' ? '<button class="sa-btn sa-small" data-review-mod-appeal="' + escapeHtml(appeal.id) + '" data-status="approved">Approve</button> <button class="sa-btn danger sa-small" data-review-mod-appeal="' + escapeHtml(appeal.id) + '" data-status="denied">Deny</button>' : escapeHtml(appeal.reviewer_note || 'Reviewed')) + '</td></tr>').join("") +
          '</tbody></table></div></section>';
        content.querySelectorAll("[data-review-appeal]").forEach((button) => button.addEventListener("click", async () => {
          const response = prompt("Optional response to the user:", "");
          if (response === null) return;
          await actionRun(() => api("update_appeal", { appeal_id: button.dataset.reviewAppeal, status: button.dataset.status, admin_response: response }), "Appeal updated.");
        }));
        content.querySelectorAll("[data-review-mod-appeal]").forEach(button => button.addEventListener("click", async () => {
          const note = prompt("Optional reviewer note:", "");
          if (note === null) return;
          await actionRun(() => api("review_moderation_appeal", {
            appeal_id: button.dataset.reviewModAppeal, status: button.dataset.status, reviewer_note: note
          }), "Moderation appeal reviewed.");
        }));
      } else if (activeTab === "verified_requests") {
        const data = await api("verified_requests");
        const requests = data.requests || [];
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">COMMUNITY TRUST</span><h1>Verified badge requests</h1><p>Review account verification submissions and approve or decline each request.</p></div></div><section class="sa-panel"><div class="sa-toolbar"><h2>Requests (' + requests.length + ')</h2></div><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Account</th><th>Reason / evidence</th><th>Submitted</th><th>Status</th><th>Decision</th></tr></thead><tbody>' +
          (requests.length ? requests.map(item => '<tr><td><strong>' + escapeHtml(item.profile?.username ? '@' + item.profile.username : item.profile?.display_name || 'Murmur user') + '</strong><div class="sa-muted">' + escapeHtml(item.user_id) + '</div></td><td>' + escapeHtml(item.reason) + (item.evidence_url ? '<div><a href="' + escapeHtml(item.evidence_url) + '" target="_blank" rel="noopener noreferrer">Open public link</a></div>' : '') + (item.reviewer_note ? '<div class="sa-muted">Previous note: ' + escapeHtml(item.reviewer_note) + '</div>' : '') + '</td><td>' + escapeHtml(dateLabel(item.created_at)) + '</td><td><span class="sa-status">' + escapeHtml(item.status) + '</span></td><td>' + (item.status === 'pending' ? '<button class="sa-btn primary sa-small" data-verified-review="' + escapeHtml(item.id) + '" data-status="approved">Approve &amp; verify</button> <button class="sa-btn danger sa-small" data-verified-review="' + escapeHtml(item.id) + '" data-status="rejected">Decline</button>' : '<span class="sa-muted">Reviewed</span>') + '</td></tr>').join('') : '<tr><td colspan="5">No verified badge requests yet.</td></tr>') +
          '</tbody></table></div></section>';
        content.querySelectorAll("[data-verified-review]").forEach(button => button.addEventListener("click", async () => {
          const note = prompt(button.dataset.status === "approved" ? "Optional note to the user:" : "Reason for declining this request:", "");
          if (note === null) return;
          if (button.dataset.status === "rejected" && !note.trim()) { notice("Add a short reason before declining."); return; }
          await actionRun(() => api("review_verified_request", { request_id: button.dataset.verifiedReview, status: button.dataset.status, reviewer_note: note }), button.dataset.status === "approved" ? "Badge request approved and account verified." : "Badge request declined.");
          responseCache.delete("verified_requests:{}");
          if (activeTab === "verified_requests") loadTab();
        }));
      } else if (activeTab === "notifications") {
        const data = await api("notifications");
        const items = data.notifications || [];
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">MODERATION</span><h1>User notifications</h1><p>Review and delete individual notifications delivered to Murmur accounts.</p></div></div><section class="sa-panel"><div class="sa-toolbar"><h2>Recent notifications (' + items.length + ')</h2><span class="sa-muted">Latest 200</span></div><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Recipient</th><th>Notification</th><th>Date / status</th><th>Action</th></tr></thead><tbody>' +
          (items.length ? items.map(item => '<tr><td><strong>' + escapeHtml(item.recipient?.username ? '@' + item.recipient.username : item.recipient?.display_name || item.recipient_id) + '</strong><div class="sa-muted">' + escapeHtml(item.recipient_id) + '</div></td><td><strong>' + escapeHtml((item.kind || "notification").replace(/[_-]/g, " ")) + '</strong><div class="sa-muted">' + escapeHtml(item.content || "") + '</div></td><td>' + escapeHtml(dateLabel(item.created_at)) + '<div class="sa-muted">' + (item.read_at ? "Read" : "Unread") + '</div></td><td><button class="sa-btn danger sa-small" data-delete-notification="' + escapeHtml(item.id) + '">Delete</button></td></tr>').join("") : '<tr><td colspan="4">No notifications found.</td></tr>') +
          '</tbody></table></div></section>';
        content.querySelectorAll("[data-delete-notification]").forEach(button => button.addEventListener("click", async () => {
          if (!confirm("Permanently delete this notification for its recipient?")) return;
          await actionRun(() => api("delete_notification", { notification_id: button.dataset.deleteNotification }), "Notification deleted.");
        }));
      } else if (activeTab === "announcements") {
        const data = await api("announcements");
        content.innerHTML = '<section class="sa-panel"><h2>Publish an announcement</h2><form id="saAnnouncementForm"><label class="sa-field-label" for="saAnnouncementTitle">Announcement title</label><select class="sa-search" id="saAnnouncementTitle" name="title" required><option value="Important Update">Important Update</option><option value="New Feature">New Feature</option><option value="Feature Update">Feature Update</option><option value="Maintenance Notice">Maintenance Notice</option><option value="Service Update">Service Update</option><option value="Security Notice">Security Notice</option><option value="Account Notice">Account Notice</option><option value="Community Guidelines">Community Guidelines</option><option value="Event Announcement">Event Announcement</option><option value="General Announcement">General Announcement</option></select><textarea class="sa-search" name="body" required maxlength="5000" rows="4" placeholder="Write the full announcement information" style="display:block;max-width:none;margin:10px 0"></textarea><div class="sa-muted">This announcement is delivered only in the Murmur notifications area. Users can tap it to open the full details.</div><div class="sa-actions"><select class="sa-search" name="kind"><option value="info">Information</option><option value="warning">Warning</option><option value="success">Success</option><option value="urgent">Urgent</option></select><button class="sa-btn primary" type="submit">Publish notification</button></div></form></section><section class="sa-panel"><h2>Published announcements</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Announcement</th><th>Type</th><th>Published</th><th>Action</th></tr></thead><tbody>' +
          (data.announcements || []).map((item) => '<tr><td><strong>' + escapeHtml(item.title) + '</strong><div class="sa-muted">' + escapeHtml(item.body) + '</div></td><td>' + escapeHtml(item.kind) + '</td><td>' + escapeHtml(dateLabel(item.published_at)) + '</td><td><button class="sa-btn danger sa-small" data-delete-announcement="' + escapeHtml(item.id) + '">Delete</button></td></tr>').join("") + '</tbody></table></div></section>';
        content.querySelector("#saAnnouncementForm").addEventListener("submit", async (event) => {
          event.preventDefault();
          const formData = new FormData(event.currentTarget);
          await actionRun(() => api("create_announcement", { title: formData.get("title"), body: formData.get("body"), kind: formData.get("kind"), is_pinned: formData.get("pinned") === "on" }), "Announcement published.");
        });
        content.querySelectorAll("[data-delete-announcement]").forEach((button) => button.addEventListener("click", async () => {
          if (!confirm("Delete this announcement?")) return;
          await actionRun(() => api("delete_announcement", { announcement_id: button.dataset.deleteAnnouncement }), "Announcement deleted.");
        }));
      } else if (activeTab === "errors") {
        const data = await api("errors");
        const items = data.errors || [];
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">DIAGNOSTICS</span><h1>Application errors</h1><p>Latest captured crashes, failed requests and browser issues. Review details before making changes.</p></div><a class="sa-btn" href="./errors.html">Open full error log</a></div>' +
          '<section class="sa-panel"><div class="sa-toolbar"><h2>Latest errors (' + Number(data.total || items.length) + ')</h2><input id="saErrorSearch" class="sa-search" type="search" placeholder="Search errors, page or account" aria-label="Search errors"></div>' +
          '<div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Time</th><th>Type</th><th>Message</th><th>Account</th><th>Page / source</th><th>Details</th></tr></thead><tbody id="saErrorRows">' +
          (items.length ? items.map((item) => '<tr data-error-row><td>' + escapeHtml(dateLabel(item.created_at)) + '</td><td><span class="sa-status">' + escapeHtml(item.kind || "unknown") + '</span></td><td>' + escapeHtml(item.message || "No message") + '<div class="sa-muted">' + escapeHtml(item.code || "") + '</div></td><td>' + escapeHtml(item.actor_key || "anonymous") + '</td><td>' + escapeHtml(item.page || item.source || "—") + (item.line ? '<div class="sa-muted">Line ' + Number(item.line) + (item.column_number ? ":" + Number(item.column_number) : "") + '</div>' : '') + '</td><td>' + (item.stack ? '<details><summary>Stack trace</summary><pre class="sa-error-stack">' + escapeHtml(item.stack) + '</pre></details>' : '—') + '</td></tr>').join("") : '<tr><td colspan="6">No errors have been recorded yet. The automatic reporter is connected to the app.</td></tr>') +
          '</tbody></table></div></section>';
        const search = content.querySelector("#saErrorSearch");
        if (search) search.addEventListener("input", () => {
          const q = search.value.toLowerCase();
          content.querySelectorAll("[data-error-row]").forEach((row) => { row.hidden = !row.textContent.toLowerCase().includes(q); });
        });
      } else if (activeTab === "system") {
        const data = await api("system");
        const countCards = Object.entries(data.counts || {}).map(([name, count]) =>
          '<article class="sa-card"><div class="sa-card-top"><span class="sa-muted">' + escapeHtml(name.replace(/_/g, " ")) +
          '</span><span class="sa-card-dot"></span></div><div class="sa-number">' + Number(count).toLocaleString() + '</div><div class="sa-card-foot">Current records</div></article>'
        ).join("");
        const errors = data.errors || [];
        const restrictions = data.restrictions || [];
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">OPERATIONS</span><h1>System health</h1><p>Read-only diagnostics and active account restrictions.</p></div><span class="sa-live"><i></i> Server response received</span></div>' +
          '<div class="sa-grid">' + countCards + '</div>' +
          '<section class="sa-panel"><h2>Recent application errors (' + errors.length + ')</h2><p>Latest 100 error records. User-agent and stack details are intentionally not shown here.</p><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Time</th><th>Type</th><th>Error</th><th>Page / source</th><th>Code</th></tr></thead><tbody>' +
          (errors.length ? errors.map((item) => '<tr><td>' + escapeHtml(dateLabel(item.created_at)) + '</td><td>' + escapeHtml(item.kind || "—") + '</td><td>' + escapeHtml(item.message || "No message") + '<div class="sa-muted">' + escapeHtml(item.fingerprint || "") + '</div></td><td>' + escapeHtml(item.page || item.source || "—") + (item.line ? '<div class="sa-muted">Line ' + Number(item.line) + '</div>' : '') + '</td><td>' + escapeHtml(item.code || "—") + '</td></tr>').join("") : '<tr><td colspan="5">No application errors recorded.</td></tr>') +
          '</tbody></table></div></section>' +
          '<section class="sa-panel"><h2>Active restrictions (' + restrictions.length + ')</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Account</th><th>Status</th><th>Reason</th><th>Starts</th><th>Ends / scheduled deletion</th></tr></thead><tbody>' +
          (restrictions.length ? restrictions.map((item) => '<tr><td>' + escapeHtml(item.user_id) + '</td><td><span class="sa-status">' + escapeHtml(item.status) + '</span></td><td>' + escapeHtml(item.reason || item.reason_code || "—") + '</td><td>' + escapeHtml(dateLabel(item.starts_at || item.created_at)) + '</td><td>' + escapeHtml(dateLabel(item.scheduled_delete_at || item.ends_at)) + '</td></tr>').join("") : '<tr><td colspan="5">No active restrictions found.</td></tr>') +
          '</tbody></table></div></section>';
      } else if (activeTab === "visitors") {
        const data = await api("visitor_analytics");
        const daily = data.daily || [];
        const pages = data.pages || [];
        const recent = data.recent || [];
        const classification = data.visitor_classification || {};
        const classificationCards = [
          ["Likely human", classification.likely_human, "Recognized browser signature"],
          ["Suspected bots", classification.suspected_bot, "Crawler or automation signature"],
          ["Unknown", classification.unknown, "Not enough browser evidence"]
        ];
        const classificationLabel = (type) => type === "likely_human" ? "Likely human" :
          (type === "suspected_bot" ? "Suspected bot" : "Unknown");
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">AUDIENCE ANALYTICS</span><h1>Visitors</h1><p>Anonymous website visits, including people who have not registered or logged in.</p></div><span class="sa-live is-live" id="saVisitorLiveStatus"><i></i> Live updates connected</span></div>' +
          '<div class="sa-grid">' +
          [['Unique devices', data.unique_visitors], ['Raw page visits', data.total_visits], ['New devices today', data.unique_visitors_today], ['Page visits today', data.visits_today_sample]].map(([label, value]) =>
            '<article class="sa-card"><div class="sa-card-top"><span class="sa-muted">' + escapeHtml(label) + '</span><span class="sa-card-dot"></span></div><div class="sa-number">' + Number(value || 0).toLocaleString() + '</div><div class="sa-card-foot">Recorded anonymous IDs</div></article>'
          ).join('') + '</div>' +
          '<section class="sa-panel"><h2>Human and bot detection</h2><p class="sa-muted">Classification uses browser and automation signatures. “Likely human” does not prove a real person; browser headers can be spoofed.</p><div class="sa-grid">' +
          classificationCards.map(([label, value, note]) =>
            '<article class="sa-card"><div class="sa-card-top"><span class="sa-muted">' + escapeHtml(label) + '</span><span class="sa-card-dot"></span></div><div class="sa-number">' + Number(value || 0).toLocaleString() + '</div><div class="sa-card-foot">' + escapeHtml(note) + '</div></article>'
          ).join('') + '</div></section>' +
          (data.sample_limited ? '<p class="sa-muted">Daily and page-visit details are based on the latest 5,000 events. Unique device total is exact.</p>' : '') +
          '<section class="sa-panel"><h2>Visits by day</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Date</th><th>Visits</th><th>Unique visitors</th></tr></thead><tbody>' +
          (daily.length ? daily.map(item => '<tr><td>' + escapeHtml(item.date) + '</td><td>' + Number(item.visits).toLocaleString() + '</td><td>' + Number(item.visitors).toLocaleString() + '</td></tr>').join('') : '<tr><td colspan="3">No visits recorded yet.</td></tr>') +
          '</tbody></table></div></section>' +
          '<section class="sa-panel"><h2>Most visited pages</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Page</th><th>Visits</th></tr></thead><tbody>' +
          (pages.length ? pages.map(item => '<tr><td>' + escapeHtml(item.path) + '</td><td>' + Number(item.visits).toLocaleString() + '</td></tr>').join('') : '<tr><td colspan="2">No page visits recorded yet.</td></tr>') +
          '</tbody></table></div></section>' +
          '<section class="sa-panel"><div class="sa-toolbar"><h2>Latest visits</h2><span class="sa-muted" id="saVisitorLastUpdated">Updated just now</span></div><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Page</th><th>Visitor ID</th><th>Classification</th><th>Detection signal</th><th>Time</th></tr></thead><tbody>' +
          (recent.length ? recent.map(item => '<tr><td>' + escapeHtml(item.page_path) + '</td><td><code>' + escapeHtml(item.visitor_id) + '</code></td><td><span class="sa-status">' + escapeHtml(classificationLabel(item.visitor_type)) + '</span></td><td>' + escapeHtml(item.detection_reason || "No signal recorded") + '</td><td>' + escapeHtml(dateLabel(item.visited_at)) + '</td></tr>').join('') : '<tr><td colspan="5">No visits recorded yet.</td></tr>') +
          '</tbody></table></div></section>' +
          '<section class="sa-panel"><h2>Phone IDs and duplicate accounts</h2><p class="sa-muted">Device links are stored in Supabase. Each linked account shows its Supabase UUID and Murmur public ID; multiple accounts linked to one device are flagged as duplicates.</p><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Device label</th><th>Phone code</th><th>Accounts on device</th><th>Account IDs</th><th>Last seen</th></tr></thead><tbody>' +
          ((data.phone_devices || []).length ? data.phone_devices.map(item => '<tr><td>' + (item.duplicate_phone ? '<span class="sa-status">' + escapeHtml(item.admin_label) + '</span>' : escapeHtml(item.admin_label)) + '</td><td><code>' + escapeHtml(item.phone_code || '') + '</code></td><td>' + Number(item.linked_accounts || 0) + '</td><td>' + ((item.accounts || []).map(account => '<div><code>' + escapeHtml(account.supabase_id) + '</code><br><small>Murmur ID: ' + escapeHtml(account.murmur_id || '—') + '</small></div>').join('<hr>') || 'No registered accounts') + '</td><td>' + escapeHtml(dateLabel(item.last_seen_at)) + '</td></tr>').join('') : '<tr><td colspan="5">No registered phone/account links yet. Accounts will appear after signing in.</td></tr>') +
          '</tbody></table></div></section>';
      } else if (activeTab === "activity") {
        const data = await api("activity");
        content.innerHTML = '<section class="sa-panel"><h2>Admin activity log</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Action</th><th>Target account</th><th>Reason</th><th>Date</th></tr></thead><tbody>' +
          (data.activity || []).map((item) => '<tr><td>' + escapeHtml(item.action) + '</td><td>' + escapeHtml(item.target_user_id || "—") + '</td><td>' + escapeHtml(item.reason || JSON.stringify(item.metadata || {})) + '</td><td>' + escapeHtml(dateLabel(item.created_at)) + '</td></tr>').join("") + '</tbody></table></div></section>';
      }
      if (run !== loadId) return;
      host.replaceChildren(...content.childNodes);
      if (activeTab === "visitors") {
        const updated = document.getElementById("saVisitorLastUpdated");
        if (updated) updated.textContent = "Updated " + new Date().toLocaleTimeString();
        const statusNode = document.getElementById("saVisitorLiveStatus");
        if (statusNode) {
          statusNode.textContent = visitorRealtimeStatus === "live" ? "Live updates connected" :
            (visitorRealtimeStatus === "reconnecting" ? "Reconnecting live updates…" : "Connecting live updates…");
          statusNode.classList.toggle("is-live", visitorRealtimeStatus === "live");
        }
      }
    } catch (error) {
      if (run !== loadId) return;
      if (window.MurmurErrors) window.MurmurErrors.report("handled", error, { page: "admin-" + activeTab });
      host.innerHTML = '<div class="sa-empty" role="alert">' + escapeHtml(error.message || "Could not load this section.") + '</div>';
      if (error.status === 401 || error.status === 403) {
        notice("Access check failed. This section is not available at your current administrator stage.");
      }
    }
  }

  async function actionRun(action, successMessage) {
    try {
      await action();
      notice(successMessage);
      await loadTab();
    } catch (error) {
      if (window.MurmurErrors) window.MurmurErrors.report("handled", error, { page: "admin-" + activeTab });
      notice(error.message || "Action failed.");
    }
  }

  async function refreshManually() {
    const button = document.getElementById("saRefresh");
    button.disabled = true;
    try {
      clearResponseCache();
      const data = await api("refresh");
      if (!data || !data.allowed) {
        const seconds = Number(data && data.retry_after_seconds || 0);
        throw new Error("Refresh is limited to once every five minutes. Try again in " + Math.ceil(seconds / 60) + " minute(s).");
      }
      await loadTab();
    } catch (error) {
      notice(error.message || "Could not refresh.");
    } finally {
      button.disabled = false;
    }
  }

  async function signOut() {
    if (permissionRefreshTimer) { clearInterval(permissionRefreshTimer); permissionRefreshTimer = null; }
    await stopVisitorLiveUpdates();
    await client.auth.signOut();
    const root = document.getElementById("supabaseAdmin");
    if (root) root.remove();
    gate.hidden = false;
    passwordInput.value = "";
    setError("");
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setError("");
    submitButton.disabled = true;
    const email = emailInput.value.trim().toLowerCase();
    try {
      const { data, error } = await client.auth.signInWithPassword({
        email,
        password: passwordInput.value
      });
      if (error) throw error;
      if (!data.session) throw new Error("Supabase did not return a valid session.");
      passwordInput.value = "";
      showShell();
    } catch (error) {
      if (error.status === 401 || error.status === 403) {
        await client.auth.signOut().catch(() => {});
      }
      setError(error.message || "Could not sign in with Supabase.");
    } finally {
      submitButton.disabled = false;
    }
  });

  document.getElementById("showPass").addEventListener("change", (event) => {
    passwordInput.type = event.target.checked ? "text" : "password";
  });

  client.auth.getSession().then(({ data, error }) => {
    if (error || !data.session) return;
    // Keep a valid Supabase session during temporary API/database failures.
    // The server still verifies the allowlist and super_admin role on every action.
    showShell();
  });
})();