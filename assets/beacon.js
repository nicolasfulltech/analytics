// readable source. edit here, then regenerate beacon.min.js (see src/beacon.rs).
(() => {
  const script = document.currentScript;
  const token = script?.getAttribute("data-site-token");
  if (!token) return;

  const endpoint = script?.getAttribute("data-endpoint") || "__ENDPOINT__";
  const headerName = "__TOKEN_HEADER__";
  const ns = "__NS__";

  const readJson = (attr) => {
    const v = script?.getAttribute(attr);
    if (!v) return null;
    try {
      return JSON.parse(v);
    } catch {
      return null;
    }
  };

  const defaultSegments =
    readJson("data-segments") ||
    script?.getAttribute("data-segment")?.split(",").filter(Boolean) ||
    [];

  const ctx = {
    user: script?.getAttribute("data-user") || null,
    userSig: script?.getAttribute("data-user-sig") || null,
    segments: defaultSegments,
  };

  const post = (payload) => {
    if (ctx.user && !payload.user) {
      payload.user = ctx.user;
      payload.user_sig = ctx.userSig;
    }
    if (!payload.segments?.length && ctx.segments.length) {
      payload.segments = [...ctx.segments];
    }
    try {
      fetch(endpoint, {
        method: "POST",
        mode: "cors",
        credentials: "omit",
        keepalive: true,
        headers: {
          "Content-Type": "application/json",
          [headerName]: token,
        },
        body: JSON.stringify(payload),
      }).catch(() => {});
    } catch {
      /* offline */
    }
  };

  const base = (type) => ({
    type,
    url: location.href,
    title: document.title,
    referer: document.referrer || null,
  });

  const withOpts = (p, opts) => {
    if (opts?.user) p.user = opts.user;
    if (opts?.user_sig) p.user_sig = opts.user_sig;
    if (opts?.segments) p.segments = opts.segments;
    return p;
  };

  const pageview = (opts) => post(withOpts(base("pageview"), opts));

  const search = (opts) => {
    if (!opts?.query) return;
    const p = base("search");
    p.search = {
      query: String(opts.query),
      result_count:
        typeof opts.result_count === "number" ? opts.result_count : null,
      results: Array.isArray(opts.results) ? opts.results : null,
      clicked_result: opts.clicked_result || null,
    };
    post(withOpts(p, opts));
  };

  const custom = (name, extra, opts) => {
    const p = base("custom");
    p.name = name ? String(name) : null;
    p.extra = extra || null;
    post(withOpts(p, opts));
  };

  // user + user_sig must come from your server, never built in the browser
  const identify = (t) => {
    if (!t?.user || !t?.user_sig) {
      ctx.user = null;
      ctx.userSig = null;
      return;
    }
    ctx.user = String(t.user);
    ctx.userSig = String(t.user_sig);
  };

  const setSegments = (list) => {
    ctx.segments = Array.isArray(list) ? [...list] : [];
  };

  window[ns] = { pageview, search, custom, identify, setSegments };

  if (document.readyState === "complete") {
    pageview();
  } else {
    window.addEventListener("load", () => pageview(), { once: true });
  }

  let lastPath = location.pathname + location.search;
  const onNav = () => {
    const path = location.pathname + location.search;
    if (path === lastPath) return;
    lastPath = path;
    pageview();
  };

  const origPush = history.pushState;
  history.pushState = function (...args) {
    origPush.apply(this, args);
    onNav();
  };
  window.addEventListener("popstate", onNav);
})();
