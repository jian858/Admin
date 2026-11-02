/* Murmur automatic error reporter: sends crashes, failed requests, broken resources and handled errors to the private error log. */
(function () {
  "use strict";
  var LOG_URL = "https://pkadftvqslkykehcqedj.supabase.co/functions/v1/murmur-error-log";
  var KEY = "sb_publishable_etoHiUGbJ96MUPzJABL12A_UiTWVxok";
  var QUEUE_KEY = "murmur-error-queue", MAX_PER_PAGE = 25, MAX_QUEUED = 30;
  var nativeFetch = window.fetch ? window.fetch.bind(window) : null;
  var seen = {}, sentCount = 0;

  function sessionToken() {
    try {
      var name = Object.keys(localStorage).filter(function (k) { return /^sb-.*-auth-token$/.test(k); })[0];
      return name ? JSON.parse(localStorage.getItem(name)).access_token || "" : "";
    } catch (e) { return ""; }
  }
  function post(item) {
    return nativeFetch(LOG_URL, {
      method: "POST", keepalive: true,
      headers: { "Content-Type": "application/json", "apikey": KEY, "Authorization": "Bearer " + (sessionToken() || KEY) },
      body: JSON.stringify(item)
    }).then(function (r) { if (!r.ok) throw new Error("log " + r.status); });
  }
  function readQueue() { try { return JSON.parse(localStorage.getItem(QUEUE_KEY) || "[]"); } catch (e) { return []; } }
  function writeQueue(list) { try { localStorage.setItem(QUEUE_KEY, JSON.stringify(list.slice(-MAX_QUEUED))); } catch (e) {} }
  function flush() {
    var list = readQueue(); if (!list.length || !nativeFetch) return;
    writeQueue([]);
    list.forEach(function (item) { post(item).catch(function () { writeQueue(readQueue().concat(item)); }); });
  }
  function report(kind, message, extra) {
    if (!nativeFetch) return;
    message = String(message || "Unknown error").slice(0, 500);
    var key = kind + "|" + message;
    if (seen[key] || sentCount >= MAX_PER_PAGE) return;
    seen[key] = true; sentCount++;
    var item = Object.assign({
      kind: kind, message: message,
      page: location.pathname.split("/").pop() || "index",
      source: location.href.split(/[?#]/)[0],
      user_agent: navigator.userAgent
    }, extra || {});
    post(item).catch(function () { writeQueue(readQueue().concat(item)); });
  }
  function reportError(kind, error, extra) {
    report(kind, error && error.message || error, Object.assign({ stack: error && error.stack ? String(error.stack).slice(0, 4000) : "" }, extra || {}));
  }

  window.addEventListener("error", function (e) {
    var t = e.target;
    if (t && t !== window && (t.src || t.href)) { report("resource", "Failed to load " + String(t.src || t.href).split(/[?#]/)[0]); return; }
    reportError("crash", e.error || e.message, { line: e.lineno || "", column_number: e.colno || "", source: e.filename ? String(e.filename).split(/[?#]/)[0] : undefined });
  }, true);
  window.addEventListener("unhandledrejection", function (e) { reportError("crash", e.reason || "Unhandled promise rejection"); });

  if (nativeFetch) {
    window.fetch = function (input, init) {
      var url = String(input && input.url || input).split(/[?#]/)[0];
      var method = (init && init.method) || (input && input.method) || "GET";
      var tracked = url.indexOf(LOG_URL) !== 0;
      return nativeFetch(input, init).then(function (r) {
        var authMistake = /\/auth\/v1\//.test(url) && r.status < 500;
        if (tracked && r.status >= 400 && !authMistake) report("api", method + " " + url + " failed", { code: String(r.status) });
        return r;
      }, function (err) {
        if (tracked) report("network", method + " " + url + " could not connect", { stack: err && err.message || "" });
        throw err;
      });
    };
  }
  window.MurmurErrors = { report: reportError };
  window.addEventListener("online", flush);
  flush();
})();