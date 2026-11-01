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
  let busy = false;

  const style = document.createElement("style");
  style.textContent = `
    .sa-shell{min-height:100vh;background:var(--bg,#f5f6f8);color:var(--text,#17202b);padding:24px;box-sizing:border-box;font:inherit}
    .sa-wrap{max-width:1180px;margin:auto}.sa-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:22px}
    .sa-brand{font-size:24px;font-weight:800;letter-spacing:-.04em}.sa-muted{color:var(--muted,#687386);font-size:13px}
    .sa-actions,.sa-tabs{display:flex;gap:8px;flex-wrap:wrap}.sa-btn{border:1px solid var(--line,#dce1e8);background:var(--surface,#fff);color:inherit;border-radius:10px;padding:10px 14px;font:inherit;font-size:13px;font-weight:650;cursor:pointer}
    .sa-btn.primary{background:#202b3b;color:white;border-color:#202b3b}.sa-btn.danger{color:#b42318}.sa-btn:disabled{opacity:.5;cursor:wait}
    .sa-tabs{margin:18px 0}.sa-tabs button[aria-current=true]{background:#202b3b;color:#fff;border-color:#202b3b}
    .sa-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.sa-card,.sa-panel{background:var(--surface,#fff);border:1px solid var(--line,#e1e5eb);border-radius:15px;padding:17px;box-shadow:0 3px 14px #15223808}
    .sa-number{font-size:28px;font-weight:800;margin-top:8px}.sa-panel{margin-top:14px;overflow:hidden}.sa-panel h2{font-size:17px;margin:0 0 14px}
    .sa-table-wrap{overflow:auto} .sa-table{width:100%;border-collapse:collapse;font-size:13px}.sa-table th,.sa-table td{text-align:left;padding:12px 10px;border-top:1px solid var(--line,#e6e9ee);vertical-align:top}
    .sa-table th{color:var(--muted,#687386);font-size:11px;text-transform:uppercase;letter-spacing:.06em}.sa-status{display:inline-block;border-radius:99px;padding:4px 8px;background:#edf1f5;font-size:11px}
    .sa-toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-bottom:12px}.sa-search{max-width:320px;width:100%;padding:10px 12px;border:1px solid var(--line,#dce1e8);border-radius:10px;background:var(--surface,#fff);color:inherit;font:inherit}
    .sa-message{padding:12px 14px;border-radius:10px;background:#f1f4f8;margin:12px 0;font-size:13px}.sa-empty{padding:28px;text-align:center;color:var(--muted,#687386)}
    .sa-cell-actions{display:flex;gap:6px;flex-wrap:wrap}.sa-small{font-size:11px;padding:7px 9px}
    @media(max-width:600px){.sa-shell{padding:14px}.sa-head{align-items:flex-start;flex-direction:column}.sa-table{min-width:680px}}
  `;
  document.head.appendChild(style);

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
    if (!response.ok) throw new Error(result.error || "Admin request failed (" + response.status + ").");
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
        <header class="sa-head">
          <div><div class="sa-brand">murmur / admin</div><div class="sa-muted" id="saIdentity">Secure Supabase administration</div></div>
          <div class="sa-actions"><button class="sa-btn" id="saRefresh" type="button">Refresh data</button><button class="sa-btn" id="saSignOut" type="button">Sign out</button></div>
        </header>
        <nav class="sa-tabs" aria-label="Admin sections">
          <button class="sa-btn" data-tab="overview" type="button">Overview</button>
          <button class="sa-btn" data-tab="users" type="button">Users</button>
          <button class="sa-btn" data-tab="reports" type="button">Reports</button>
          <button class="sa-btn" data-tab="posts" type="button">Posts</button>
        </nav>
        <div id="saNotice" class="sa-message" hidden role="status"></div>
        <section id="saContent" aria-live="polite"><div class="sa-empty">Loading secure dashboard…</div></section>
      </div>`;
    root.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => {
      activeTab = button.dataset.tab;
      loadTab();
    }));
    root.querySelector("#saRefresh").addEventListener("click", refreshManually);
    root.querySelector("#saSignOut").addEventListener("click", signOut);
    loadTab();
  }

  function notice(message) {
    const node = document.getElementById("saNotice");
    if (!node) return;
    node.textContent = message || "";
    node.hidden = !message;
  }

  function updateTabs() {
    document.querySelectorAll("[data-tab]").forEach((button) => {
      button.setAttribute("aria-current", String(button.dataset.tab === activeTab));
    });
  }

  async function loadTab() {
    if (busy) return;
    busy = true;
    updateTabs();
    const content = document.getElementById("saContent");
    content.innerHTML = '<div class="sa-empty">Loading…</div>';
    try {
      if (activeTab === "overview") {
        const data = await api("overview");
        document.getElementById("saIdentity").textContent = data.admin.email + " · " + data.admin.role;
        content.innerHTML = '<div class="sa-grid">' + Object.entries(data.counts).map(([name, count]) =>
          '<article class="sa-card"><div class="sa-muted">' + escapeHtml(name.replace(/_/g, " ")) +
          '</div><div class="sa-number">' + Number(count).toLocaleString() + '</div></article>'
        ).join("") + '</div><section class="sa-panel"><h2>Administration status</h2><div class="sa-muted">Authenticated through Supabase Auth. All privileged actions are verified by the server-side admin allowlist.</div></section>';
      } else if (activeTab === "users") {
        const data = await api("users");
        content.innerHTML = '<section class="sa-panel"><div class="sa-toolbar"><h2>Users</h2><input class="sa-search" id="saSearch" type="search" placeholder="Search users" aria-label="Search users"></div><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Account</th><th>Username</th><th>Created</th><th>Status</th><th>Action</th></tr></thead><tbody>' +
          data.users.map((user) => '<tr data-user-row="' + escapeHtml(user.id) + '"><td><strong>' + escapeHtml(user.display_name || "Unnamed") + '</strong><div class="sa-muted">' + escapeHtml(user.id) + '</div></td><td>' + escapeHtml(user.username || "—") + '</td><td>' + escapeHtml(dateLabel(user.created_at)) + '</td><td><span class="sa-status">' + (user.is_suspended ? "Suspended" : "Active") + '</span>' + (user.suspension_reason ? '<div class="sa-muted">' + escapeHtml(user.suspension_reason) + '</div>' : '') + '</td><td><div class="sa-cell-actions">' +
          (user.is_suspended ? '<button class="sa-btn sa-small" data-unsuspend="' + escapeHtml(user.id) + '">Restore</button>' : '<button class="sa-btn danger sa-small" data-suspend="' + escapeHtml(user.id) + '">Suspend</button>') +
          '</div></td></tr>').join("") + '</tbody></table></div></section>';
        document.getElementById("saSearch").addEventListener("input", (event) => {
          const query = event.target.value.toLowerCase();
          content.querySelectorAll("[data-user-row]").forEach((row) => { row.hidden = !row.textContent.toLowerCase().includes(query); });
        });
        content.querySelectorAll("[data-suspend]").forEach((button) => button.addEventListener("click", async () => {
          const reason = prompt("Enter the reason for suspension:");
          if (!reason || !reason.trim()) return;
          await actionRun(() => api("set_user_status", { user_id: button.dataset.suspend, suspended: true, reason: reason.trim() }), "Account suspended.");
        }));
        content.querySelectorAll("[data-unsuspend]").forEach((button) => button.addEventListener("click", async () => {
          await actionRun(() => api("set_user_status", { user_id: button.dataset.unsuspend, suspended: false }), "Account restored.");
        }));
      } else if (activeTab === "reports") {
        const data = await api("reports");
        content.innerHTML = '<section class="sa-panel"><h2>Reports</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Reason / details</th><th>Reported user</th><th>Date</th><th>Status</th><th>Action</th></tr></thead><tbody>' +
          data.reports.map((report) => '<tr><td><strong>' + escapeHtml(report.reason || "No reason") + '</strong><div class="sa-muted">' + escapeHtml(report.details || "") + '</div><div class="sa-muted">Report ' + escapeHtml(report.id) + '</div></td><td>' + escapeHtml(report.reported_user_id || "—") + '</td><td>' + escapeHtml(dateLabel(report.created_at)) + '</td><td><span class="sa-status">' + escapeHtml(report.status || "open") + '</span></td><td><select class="sa-search sa-small" data-report-status="' + escapeHtml(report.id) + '"><option value="open">Open</option><option value="reviewing">Reviewing</option><option value="resolved">Resolved</option><option value="dismissed">Dismissed</option></select></td></tr>').join("") + '</tbody></table></div></section>';
        content.querySelectorAll("[data-report-status]").forEach((select) => {
          const report = data.reports.find((item) => item.id === select.dataset.reportStatus);
          select.value = report?.status || "open";
          select.addEventListener("change", async () => actionRun(() => api("update_report", { report_id: select.dataset.reportStatus, status: select.value }), "Report status updated."));
        });
      } else if (activeTab === "posts") {
        const data = await api("posts");
        content.innerHTML = '<section class="sa-panel"><h2>Posts</h2><div class="sa-table-wrap"><table class="sa-table"><thead><tr><th>Post</th><th>Author</th><th>Visibility</th><th>Created</th><th>Action</th></tr></thead><tbody>' +
          data.posts.map((post) => '<tr><td>' + escapeHtml(post.content || (post.media_type || "Media post")) + '<div class="sa-muted">' + escapeHtml(post.id) + '</div></td><td>' + escapeHtml(post.author_id) + '</td><td>' + escapeHtml(post.visibility || "—") + '</td><td>' + escapeHtml(dateLabel(post.created_at)) + '</td><td><button class="sa-btn danger sa-small" data-delete-post="' + escapeHtml(post.id) + '">Delete</button></td></tr>').join("") + '</tbody></table></div></section>';
        content.querySelectorAll("[data-delete-post]").forEach((button) => button.addEventListener("click", async () => {
          if (!confirm("Permanently delete this post?")) return;
          await actionRun(() => api("delete_post", { post_id: button.dataset.deletePost }), "Post deleted.");
        }));
      }
      notice("");
    } catch (error) {
      content.innerHTML = '<div class="sa-empty">' + escapeHtml(error.message || "Could not load this section.") + '</div>';
    } finally {
      busy = false;
    }
  }

  async function actionRun(action, successMessage) {
    try {
      await action();
      notice(successMessage);
      await loadTab();
    } catch (error) {
      notice(error.message || "Action failed.");
    }
  }

  async function refreshManually() {
    const button = document.getElementById("saRefresh");
    button.disabled = true;
    try {
      const { data, error } = await client.rpc("consume_murmur_manual_refresh");
      if (error) throw error;
      if (!data.allowed) {
        const seconds = Number(data.retry_after_seconds || 0);
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
      await api("overview");
      passwordInput.value = "";
      showShell();
    } catch (error) {
      await client.auth.signOut().catch(() => {});
      setError(error.message || "Could not sign in with Supabase.");
    } finally {
      submitButton.disabled = false;
    }
  });

  document.getElementById("showPass").addEventListener("change", (event) => {
    passwordInput.type = event.target.checked ? "text" : "password";
  });

  client.auth.getSession().then(async ({ data, error }) => {
    if (error || !data.session) return;
    try {
      await api("overview");
      showShell();
    } catch {
      await client.auth.signOut();
    }
  });
})();