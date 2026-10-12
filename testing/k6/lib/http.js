import http from 'k6/http';
import encoding from 'k6/encoding';
import exec from 'k6/execution';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { cfg } from './config.js';
import { recordFailure } from './failures.js';

export const pageDuration = new Trend('magento_page_duration', true);
export const errorRate = new Rate('magento_errors');
export const ordersPlaced = new Counter('magento_orders_placed');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) k6/MagentoBenchmark/1.0';

export function baseHeaders() {
  const headers = {
    'User-Agent': UA,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  };
  if (cfg.basicAuthUser && cfg.basicAuthPassword) {
    headers.Authorization = `Basic ${encoding.b64encode(`${cfg.basicAuthUser}:${cfg.basicAuthPassword}`)}`;
  }
  return headers;
}

export const AJAX = { 'X-Requested-With': 'XMLHttpRequest' };
export const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=UTF-8',
  Accept: 'application/json',
  'X-Requested-With': 'XMLHttpRequest',
};

export function url(path) {
  if (/^https?:\/\//.test(path)) return path;
  return `${cfg.baseUrl}/${path.replace(/^\//, '')}`;
}

// Build a query string; arrays/objects are not needed by any flow so keep it flat.
export function qs(params) {
  return Object.keys(params)
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
    .join('&');
}

function bust(u) {
  if (!cfg.fpcBust) return u;
  const sep = u.includes('?') ? '&' : '?';
  return `${u}${sep}fpc=${exec.vu.idInTest}_${exec.vu.iterationInScenario}_${Date.now()}`;
}

// Runs the k6 checks and feeds magento_errors. `expect` entries are either a
// substring the body must contain, a RegExp, or a function(res) => bool.
export function verify(res, name, expect, okStatus) {
  const statuses = okStatus || [200];
  const checks = {};
  checks[`${name}: status ${statuses.join('/')}`] = (r) => statuses.includes(r.status);
  for (const e of expect || []) {
    if (typeof e === 'function') {
      checks[`${name}: ${e.label || 'custom check'}`] = e;
    } else if (e instanceof RegExp) {
      checks[`${name}: matches ${e.source.slice(0, 40)}`] = (r) => e.test(r.body || '');
    } else {
      checks[`${name}: contains "${String(e).slice(0, 40)}"`] = (r) => (r.body || '').includes(e);
    }
  }
  const ok = check(res, checks);
  errorRate.add(!ok);
  if (!ok) {
    const failed = Object.keys(checks).filter((label) => {
      try {
        return !checks[label](res);
      } catch (e) {
        return true;
      }
    });
    recordFailure(res, name, failed);
    if (cfg.debug) console.warn(`[VU ${exec.vu.idInTest}] ${name} failed: ${res.status} ${res.url}`);
  }
  return ok;
}

// GET a page. `name` is the metric tag, so URLs with ids don't explode cardinality.
export function get(path, name, opts) {
  const o = opts || {};
  const target = o.noBust ? url(path) : bust(url(path));
  const res = http.get(target, {
    headers: Object.assign(baseHeaders(), o.headers || {}),
    tags: { name },
    redirects: o.redirects === undefined ? 10 : o.redirects,
  });
  if (!o.headers || !o.headers['X-Requested-With']) pageDuration.add(res.timings.duration, { name });
  verify(res, name, o.expect, o.status);
  return res;
}

export function post(path, body, name, opts) {
  const o = opts || {};
  const res = http.post(url(path), body, {
    headers: Object.assign(baseHeaders(), o.headers || {}),
    tags: { name },
    redirects: o.redirects === undefined ? 10 : o.redirects,
  });
  verify(res, name, o.expect, o.status);
  return res;
}

export function postJson(path, payload, name, opts) {
  const o = Object.assign({}, opts || {});
  o.headers = Object.assign({}, JSON_HEADERS, o.headers || {});
  return post(path, JSON.stringify(payload), name, o);
}

export function think() {
  if (cfg.thinkMs <= 0) return;
  const jitter = (Math.random() * 2 - 1) * cfg.thinkDeviationMs;
  sleep(Math.max(0, cfg.thinkMs + jitter) / 1000);
}

export function pick(list) {
  return list[Math.floor(Math.random() * list.length)];
}

export function pickDistinct(list, n) {
  const copy = list.slice();
  const out = [];
  while (out.length < n && copy.length) out.push(copy.splice(Math.floor(Math.random() * copy.length), 1)[0]);
  return out;
}

// Pick a key from a { key: weight } map.
export function weighted(weights) {
  const entries = Object.entries(weights).filter(([, w]) => w > 0);
  const total = entries.reduce((sum, [, w]) => sum + w, 0);
  let roll = Math.random() * total;
  for (const [key, w] of entries) {
    roll -= w;
    if (roll <= 0) return key;
  }
  return entries[entries.length - 1][0];
}

export function match(body, re, group) {
  const m = (body || '').match(re);
  return m ? m[group === undefined ? 1 : group] : null;
}

// Full-page-cached HTML can carry someone else's form_key, so (like the JMX)
// plant our own form_key cookie; Magento registers it into the session.
export function initFormKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = '';
  for (let i = 0; i < 16; i++) key += chars[Math.floor(Math.random() * chars.length)];
  http.cookieJar().set(cfg.baseUrl, 'form_key', key, { path: '/' });
  return key;
}

export function formKey(res) {
  return (
    match(res.body, /name="form_key"\s+type="hidden"\s+value="([^"]+)"/) ||
    match(res.body, /name=["']form_key["']\s+value=["']([^"']+)["']/) ||
    match(res.body, /["']formKey["']\s*:\s*["']([^"']+)["']/)
  );
}

export function json(res) {
  try {
    return res.json();
  } catch (e) {
    return null;
  }
}

export function uniq(label) {
  return `${label}${Date.now()}-${exec.vu.idInTest}-${Math.floor(Math.random() * 1e6)}`;
}
