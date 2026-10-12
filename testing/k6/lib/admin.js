// Admin UI client.
//
// "Add Secret Key to URLs" stays enabled on the store. The keys are an HMAC of
// route/controller/action + session form key using the crypt key, so we can't
// compute them; instead every admin response is scanned for keyed URLs and the
// key is remembered per route/controller/action (params don't affect it).
// Keys are tied to the session, so they are dropped on every login.
import http from 'k6/http';
import exec from 'k6/execution';
import { cfg } from './config.js';
import { baseHeaders, verify, match, pageDuration, AJAX } from './http.js';

export class AdminClient {
  constructor(username, password) {
    this.username = username;
    this.password = password;
    this.keys = {};
    this.formKey = null;
    this.keyRe = new RegExp(`/${cfg.adminPath}/((?:[A-Za-z0-9_]+/)+?)key/([0-9a-f]{32,128})`, 'g');
  }

  base() {
    return `${cfg.baseUrl}/${cfg.adminPath}`;
  }

  harvest(res) {
    // URLs appear plain, HTML-entity (&#x2F;), JSON-escaped (\/) and unicode-escaped (\u002F); the final
    // URL after redirects carries a key too
    const body = `${res.url || ''}\n${res.body || ''}`
      .replace(/&#x2F;/gi, '/')
      .replace(/&#x3A;/gi, ':')
      .replace(/\\u002F/gi, '/')
      .replace(/\\u003A/gi, ':')
      .replace(/\\\//g, '/');
    const fk = match(body, /var FORM_KEY = '([^']+)'/) || match(body, /name="form_key" type="hidden" value="([^"]+)"/);
    if (fk) this.formKey = fk;
    this.keyRe.lastIndex = 0;
    let m;
    while ((m = this.keyRe.exec(body)) !== null) {
      const segs = m[1].split('/').filter(Boolean);
      const route = `${segs[0]}/${segs[1] || 'index'}/${segs[2] || 'index'}`;
      this.keys[route] = m[2];
    }
  }

  hasKey(route) {
    return Boolean(this.keys[route]);
  }

  // route: 'catalog/product/edit'; params: 'id/5/' path params; query: raw query string
  link(route, params, query) {
    const key = this.keys[route];
    if (!key && cfg.debug) console.warn(`[VU ${exec.vu.idInTest}] no admin secret key harvested for ${route}`);
    let u = `${this.base()}/${route}/${params || ''}`;
    if (key) u += `key/${key}/`;
    if (query) u += `?${query}`;
    return u;
  }

  isLoginPage(res) {
    return (res.body || '').includes('name="login[username]"');
  }

  request(method, route, opts, retried) {
    const o = opts || {};
    const target = route.startsWith('http') ? route : this.link(route, o.params, o.query);
    let body = o.body;
    if (method === 'POST' && body && typeof body === 'object' && !o.raw) {
      body = Object.assign({ form_key: this.formKey }, body);
    }
    const res = http.request(method, target, body, {
      headers: Object.assign(baseHeaders(), o.ajax ? AJAX : {}, o.headers || {}),
      tags: { name: o.name },
    });
    // A concurrent login with the same admin user ends our session: log in again once.
    if (!retried && !o.noRetry && this.isLoginPage(res)) {
      if (cfg.debug) console.warn(`[VU ${exec.vu.idInTest}] admin session lost on ${o.name}, re-login`);
      this.login();
      return this.request(method, route, opts, true);
    }
    this.harvest(res);
    if (!o.ajax) pageDuration.add(res.timings.duration, { name: o.name });
    verify(res, o.name, o.expect, o.status);
    return res;
  }

  get(route, name, opts) {
    return this.request('GET', route, Object.assign({ name }, opts || {}));
  }

  post(route, body, name, opts) {
    return this.request('POST', route, Object.assign({ name, body }, opts || {}));
  }

  login() {
    this.keys = {};
    this.formKey = null;
    const page = http.get(`${this.base()}/`, { headers: baseHeaders(), tags: { name: 'Admin Login Page' } });
    this.harvest(page);
    verify(page, 'Admin Login Page', ['<title>Magento Admin</title>']);
    const res = http.post(
      `${this.base()}/admin/dashboard/`,
      { dummy: '', form_key: this.formKey, 'login[username]': this.username, 'login[password]': this.password },
      { headers: baseHeaders(), tags: { name: 'Admin Login Submit' } }
    );
    this.harvest(res);
    // the login page also has var FORM_KEY; only a logged-in page has the logout link
    const ok = verify(res, 'Admin Login Submit', [
      Object.assign((r) => !this.isLoginPage(r) && this.hasKey('admin/auth/logout'), { label: 'logged in' }),
    ]);
    if (!ok) {
      const msg = match(res.body, /<div data-ui-id="messages-message-error"[^>]*>\s*([^<]+)/);
      const hint = /captcha/i.test(msg || '')
        ? ' (admin CAPTCHA after failed logins: set admin/captcha/enable=0 and clear the captcha_log table)'
        : '';
      console.error(`Admin login failed for ${this.username}${msg ? `: ${msg.trim()}` : ''}${hint}`);
    }
    return ok;
  }

  logout() {
    if (!this.hasKey('admin/auth/logout')) return;
    this.get('admin/auth/logout', 'Admin Logout', { noRetry: true });
  }

  // Admin UI listing (mui/index/render) request; returns parsed JSON or null
  grid(namespace, extra, name) {
    const params = Object.assign(
      {
        namespace,
        search: '',
        'filters[placeholder]': 'true',
        'paging[pageSize]': '20',
        'paging[current]': '1',
        'sorting[field]': 'entity_id',
        'sorting[direction]': 'asc',
        isAjax: 'true',
      },
      extra || {}
    );
    const query = Object.keys(params)
      .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
      .join('&');
    const res = this.get('mui/index/render', name, {
      query,
      ajax: true,
      // without this Magento renders the listing as HTML instead of JSON
      headers: { Accept: 'application/json, text/javascript, */*; q=0.01' },
      expect: [Object.assign((r) => /^\s*\{.*"totalRecords"/s.test(r.body || ''), { label: 'grid json' })],
    });
    try {
      return res.json();
    } catch (e) {
      return null;
    }
  }
}
