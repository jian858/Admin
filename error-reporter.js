/* Murmur automatic error reporter.
   Reports browser crashes, failed resources, API/network failures and handled errors. */
(function () {
  "use strict";
  var LOG_URL = "https://pkadftvqslkykehcqedj.supabase.co/functions/v1/murmur-error-log";
  var KEY = "sb_publishable_etoHiUGbJ96MUPzJABL12A_UiTWVxok";
  var QUEUE_KEY = "murmur-error-queue", MAX_PER_PAGE = 25, MAX_QUEUED = 30;
  var nativeFetch = window.fetch ? window.fetch.bind(window) : null;
  var seen = Object.create(null), sentCount = 0;
  function storedSupabaseToken() {
    try {
      var keys = Object.keys(localStorage);
      for (var i = 0; i < keys.length; i++) {
        if (/^sb-.*-auth-token$/.test(keys[i])) {
          var value = JSON.parse(localStorage.getItem(keys[i]) || "{}");
          if (value.access_token) return value.access_token;
        }
      }
    } catch (_) {}
    return "";
  }
  function sessionToken() {
    try {
      if (typeof window.MurmurErrorTokenProvider === "function") {
        return Promise.resolve(window.MurmurErrorTokenProvider()).then(function (token) {
          return token || storedSupabaseToken();
        }).catch(storedSupabaseToken);
      }
    } catch (_) {}
    return Promise.resolve(storedSupabaseToken());
  }
  function readQueue() { try { return JSON.parse(localStorage.getItem(QUEUE_KEY) || "[]"); } catch (_) { return []; } }
  function writeQueue(list) { try { localStorage.setItem(QUEUE_KEY, JSON.stringify(list.slice(-MAX_QUEUED))); } catch (_) {} }
  function post(item) {
    if (!nativeFetch) return Promise.reject(new Error("Fetch unavailable"));
    return sessionToken().then(function (token) {
      return nativeFetch(LOG_URL, {
        method: "POST", keepalive: true,
        headers: { "Content-Type": "application/json", "apikey": KEY, "Authorization": "Bearer " + (token || KEY) },
        body: JSON.stringify(item)
      });
    }).then(function (response) {
      if (!response.ok) throw new Error("error log " + response.status);
    });
  }
  function flush() {
    var list = readQueue();
    if (!list.length || !nativeFetch) return;
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
    var message = error && error.message ? error.message : String(error || "Unknown error");
    report(kind, message, Object.assign({ stack: error && error.stack ? String(error.stack).slice(0, 4000) : "" }, extra || {}));
  }
  window.addEventListener("error", function (event) {
    var target = event.target;
    if (target && target !== window && (target.src || target.href)) {
      report("resource", "Failed to load " + String(target.src || target.href).split(/[?#]/)[0]);
      return;
    }
    reportError("crash", event.error || event.message, {
      line: event.lineno || null, column_number: event.colno || null,
      source: event.filename ? String(event.filename).split(/[?#]/)[0] : undefined
    });
  }, true);
  window.addEventListener("unhandledrejection", function (event) { reportError("crash", event.reason || "Unhandled promise rejection"); });
  if (nativeFetch) {
    window.fetch = function (input, init) {
      var url = String(input && input.url || input).split(/[?#]/)[0];
      var method = (init && init.method) || (input && input.method) || "GET";
      var tracked = url.indexOf(LOG_URL) !== 0;
      return nativeFetch(input, init).then(function (response) {
        var expectedAuth = /\/auth\/v1\//.test(url) && response.status < 500;
        if (tracked && response.status >= 400 && !expectedAuth) report("api", method + " " + url + " failed", { code: String(response.status) });
        return response;
      }, function (error) {
        if (tracked) report("network", method + " " + url + " could not connect", { stack: error && error.message || "" });
        throw error;
      });
    };
  }
  window.MurmurErrors = { report: reportError, flush: flush };
  window.addEventListener("online", flush);
  flush();
})();
