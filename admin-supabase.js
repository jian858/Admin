/* Murmur Admin — Supabase-only client.
   Authentication uses Supabase Auth. Every privileged read/write is performed
   by the murmur-admin-supabase Edge Function, which verifies the allowlist. */
(function () {
  "use strict";

  const SUPABASE_URL = "https://pkadftvqslkykehcqedj.supabase.co";
  const SUPABASE_KEY = "sb_publishable_etoHiUGbJ96MUPzJABL12A_UiTWVxok";
  const ADMIN_EMAIL = "jiancarlopadua9@gmail.com";
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
  let activeTab = "overview";
  let usersPage = 1;
  let usersQuery = "";
  let usersStatus = "all";
  let loadId = 0;

  function setError(message) {
    errorBox.textContent = message || "";
    errorBox.hidden = !message;
  }

  async function api(action, payload) {
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
    return result;
  }

  function showShell() {
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
          <div class="sa-actions"><span class="sa-role">SUPER ADMIN</span><button class="sa-btn" id="saTheme" type="button" aria-label="Toggle theme">Theme</button><button class="sa-btn" id="saRefresh" type="button">Refresh data</button><button class="sa-btn" id="saSignOut" type="button">Sign out</button></div>
        </header><nav class="sa-tabs" aria-label="Admin sections">
          <button class="sa-tab" data-tab="overview" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="5" rx="2"/><rect x="13" y="10" width="8" height="11" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/></svg></span>Overview</button>
          <button class="sa-tab" data-tab="users" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><circle cx="17" cy="9" r="2.6"/><path d="M17 14c2.8 0 4.7 1.8 4.7 4.5"/></svg></span>Users</button>
          <button class="sa-tab" data-tab="reports" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg></span>Reports</button>
          <button class="sa-tab" data-tab="posts" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg></span>Posts</button>
          <button class="sa-tab" data-tab="appeals" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><path d="m12 3 8 9-8 9-8-9z"/><path d="M12 8v5m0 3h.01"/></svg></span>Appeals</button>
          <button class="sa-tab" data-tab="announcements" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><path d="m3 11 18-5v12L3 13z"/><path d="m7 14 2 7h5l-3-6"/></svg></span>Announcements</button>
          <button class="sa-tab" data-tab="errors" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><path d="M12 3 2.8 19h18.4L12 3Z"/><path d="M12 9v4m0 3h.01"/></svg></span>Errors</button>
          <button class="sa-tab" data-tab="system" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4M7 9h3m4 0h3m-10 4h10"/></svg></span>System</button>
          <button class="sa-tab" data-tab="activity" type="button"><span class="sa-tab-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span>Activity</button>
        </nav></div>
        <div id="saNotice" class="sa-message" hidden role="status"></div>
        <section id="saContent" aria-live="polite"><div class="sa-empty">Loading secure dashboard…</div></section>
      </div>`;
    root.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => {
      activeTab = button.dataset.tab;
      notice("");
      loadTab();
    }));
    root.querySelector("#saRefresh").addEventListener("click", refreshManually);
    root.querySelector("#saSignOut").addEventListener("click", signOut);
    root.querySelector("#saTheme").addEventListener("click", toggleTheme);
    loadTab();
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

  async function loadTab() {
    const run = ++loadId;
    updateTabs();
    const host = document.getElementById("saContent");
    const content = document.createElement("div");
    host.innerHTML = '<div class="sa-empty">Loading…</div>';
    try {
      if (activeTab === "overview") {
        const data = await api("overview");
        document.getElementById("saIdentity").textContent = data.admin.email + " · " + data.admin.role;
        content.innerHTML = '<div class="sa-section-heading"><div><span class="sa-kicker">CONTROL CENTER</span><h1>Overview</h1><p>Monitor your Murmur community and system activity.</p></div><span class="sa-live"><i></i> Connected session</span></div><div class="sa-grid">' + Object.entries(data.counts).map(([name, count]) =>
          '<article class="sa-card"><div class="sa-card-top"><span class="sa-muted">' + escapeHtml(name.replace(/_/g, " ")) +
          '</span><span class="sa-card-dot"></span></div><div class="sa-number">' + Number(count).toLocaleString() + '</div><div class="sa-card-foot">Current records</div></article>'
        ).join("") + '</div><section class="sa-panel sa-security-panel"><div class="sa-security-mark"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5 9-10"/></svg></div><div><h2>Administration protected</h2><p>Supabase Auth is active. Every privileged action is checked by the server-side Super Admin allowlist.</p></div></section>';
      } else if (activeTab === "users") {
        const data = await api("users", { page: usersPage, q: usersQuery, status: usersStatus });
        content.innerHTML = '<section class="sa-panel"><div class="sa-toolbar"><h2>Users</h2><form id="saUserSearch" class="sa-actions"><input class="sa-search" id="saSearch" type="search" value="' + escapeHtml(usersQuery) + '" placeholder="Search username, name or ID" aria-label="Search users"><select class="sa-search" id="saUserStatus" aria-label="Filter account status"><option value="all">All accounts</option><option value="active">Active</option><option value="suspended">Suspended</option></select><button class="sa-btn primary" type="submit">Search</button></form></div><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Account</th><th>Username</th><th>Created</th><th>Status</th><th>Action</th></tr></thead><tbody>' +
          (data.users || []).map((user) => '<tr data-user-row="' + escapeHtml(user.id) + '"><td><strong>' + escapeHtml(user.display_name || "Unnamed") + '</strong><div class="sa-muted">' + escapeHtml(user.id) + '</div></td><td>' + escapeHtml(user.username || "—") + '</td><td>' + escapeHtml(dateLabel(user.created_at)) + '</td><td><span class="sa-status">' + (user.is_suspended ? "Suspended" : "Active") + '</span>' + (user.suspension_reason ? '<div class="sa-muted">' + escapeHtml(user.suspension_reason) + '</div>' : '') + '</td><td><div class="sa-cell-actions">' +
          (user.is_suspended ? '<button class="sa-btn sa-small" data-unsuspend="' + escapeHtml(user.id) + '">Restore</button>' : '<button class="sa-btn danger sa-small" data-suspend="' + escapeHtml(user.id) + '">Suspend</button><button class="sa-btn danger sa-small" data-schedule-delete="' + escapeHtml(user.id) + '">Schedule deletion</button>') +
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
        content.querySelectorAll("[data-suspend]").forEach((button) => button.addEventListener("click", async () => {
          const reason = prompt("Enter the reason for suspension:");
          if (!reason || !reason.trim()) return;
          const duration = prompt("Suspension duration in hours. Leave blank for indefinite suspension:", "24");
          if (duration === null) return;
          await actionRun(() => api("set_user_status", { user_id: button.dataset.suspend, suspended: true, reason: reason.trim(), duration_hours: duration.trim() || null }), "Account suspended.");
        }));
        content.querySelectorAll("[data-unsuspend]").forEach((button) => button.addEventListener("click", async () => {
          await actionRun(() => api("set_user_status", { user_id: button.dataset.unsuspend, suspended: false }), "Account restored.");
        }));
        content.querySelectorAll("[data-schedule-delete]").forEach((button) => button.addEventListener("click", async () => {
          const reason = prompt("Enter the reason for account deletion:");
          if (!reason || !reason.trim()) return;
          const when = prompt("Enter the deletion date and time (example: 2026-12-01T09:00):");
          if (!when) return;
          const date = new Date(when);
          if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) { notice("Choose a valid future date and time."); return; }
          if (!confirm("Schedule this account for deletion? The account will be suspended immediately.")) return;
          await actionRun(() => api("schedule_delete", { user_id: button.dataset.scheduleDelete, reason: reason.trim(), delete_at: date.toISOString() }), "Deletion scheduled. Final deletion still requires the trusted server deletion worker.");
        }));
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
        content.querySelectorAll("[data-delete-post]").forEach((button) => button.addEventListener("click", async () => {
          if (!confirm("Permanently delete this post?")) return;
          await actionRun(() => api("delete_post", { post_id: button.dataset.deletePost }), "Post deleted.");
        }));
      } else if (activeTab === "appeals") {
        const data = await api("appeals");
        content.innerHTML = '<section class="sa-panel"><h2>Account appeals</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Appeal</th><th>Account</th><th>Submitted</th><th>Status</th><th>Review</th></tr></thead><tbody>' +
          (data.appeals || []).map((appeal) => '<tr><td>' + escapeHtml(appeal.message) + '<div class="sa-muted">' + escapeHtml(appeal.id) + '</div></td><td>' + escapeHtml(appeal.user_id) + '</td><td>' + escapeHtml(dateLabel(appeal.created_at)) + '</td><td><span class="sa-status">' + escapeHtml(appeal.status) + '</span></td><td><button class="sa-btn sa-small" data-review-appeal="' + escapeHtml(appeal.id) + '" data-status="reviewing">Review</button> <button class="sa-btn sa-small" data-review-appeal="' + escapeHtml(appeal.id) + '" data-status="approved">Approve</button> <button class="sa-btn danger sa-small" data-review-appeal="' + escapeHtml(appeal.id) + '" data-status="rejected">Reject</button></td></tr>').join("") + '</tbody></table></div></section>';
        content.querySelectorAll("[data-review-appeal]").forEach((button) => button.addEventListener("click", async () => {
          const response = prompt("Optional response to the user:", "");
          if (response === null) return;
          await actionRun(() => api("update_appeal", { appeal_id: button.dataset.reviewAppeal, status: button.dataset.status, admin_response: response }), "Appeal updated.");
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
          (items.length ? items.map((item) => '<tr data-error-row><td>' + escapeHtml(dateLabel(item.created_at)) + '</td><td><span class="sa-status">' + escapeHtml(item.kind || "unknown") + '</span></td><td>' + escapeHtml(item.message || "No message") + '<div class="sa-muted">' + escapeHtml(item.code || "") + '</div></td><td>' + escapeHtml(item.firebase_uid || "anonymous") + '</td><td>' + escapeHtml(item.page || item.source || "—") + (item.line ? '<div class="sa-muted">Line ' + Number(item.line) + (item.column_number ? ":" + Number(item.column_number) : "") + '</div>' : '') + '</td><td>' + (item.stack ? '<details><summary>Stack trace</summary><pre class="sa-error-stack">' + escapeHtml(item.stack) + '</pre></details>' : '—') + '</td></tr>').join("") : '<tr><td colspan="6">No errors have been recorded yet. The automatic reporter is connected to the app.</td></tr>') +
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
      } else if (activeTab === "activity") {
        const data = await api("activity");
        content.innerHTML = '<section class="sa-panel"><h2>Admin activity log</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Action</th><th>Target account</th><th>Reason</th><th>Date</th></tr></thead><tbody>' +
          (data.activity || []).map((item) => '<tr><td>' + escapeHtml(item.action) + '</td><td>' + escapeHtml(item.target_user_id || "—") + '</td><td>' + escapeHtml(item.reason || JSON.stringify(item.metadata || {})) + '</td><td>' + escapeHtml(dateLabel(item.created_at)) + '</td></tr>').join("") + '</tbody></table></div></section>';
      }
      if (run !== loadId) return;
      host.replaceChildren(...content.childNodes);
    } catch (error) {
      if (run !== loadId) return;
      if (window.MurmurErrors) window.MurmurErrors.report("handled", error, { page: "admin-" + activeTab });
      host.innerHTML = '<div class="sa-empty" role="alert">' + escapeHtml(error.message || "Could not load this section.") + '</div>';
      if (error.status === 401 || error.status === 403) {
        notice("Access check failed. Please sign in with the authorized Super Admin account.");
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
    if (email !== ADMIN_EMAIL) {
      setError("This email is not the authorized admin account.");
      submitButton.disabled = false;
      return;
    }
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