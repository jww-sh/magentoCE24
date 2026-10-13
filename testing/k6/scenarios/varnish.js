// Varnish full-page-cache behaviour checks (.upsun/varnish.vcl), read from the
// X-Magento-Cache-Debug header vcl_deliver adds. Runs once per test run (smoke and
// the load profiles) and is held to a 100% threshold via the suite:varnish tag.
//
// Every check uses a fresh cache-busting query string so results don't depend on
// what earlier runs left in the cache.
import http from 'k6/http';
import exec from 'k6/execution';
import { check, group } from 'k6';
import { cfg, PREFIX } from '../lib/config.js';
import { baseHeaders, url, errorRate, match } from '../lib/http.js';
import { recordFailure } from '../lib/failures.js';
import { customerLogin, customerLogout } from './storefront.js';
import { customerToken } from './graphql.js';

const TAGS = { suite: 'varnish' };

function cacheState(res) {
  return res.headers['X-Magento-Cache-Debug'] || 'none';
}

function expect(res, name, predicate, label) {
  const ok = check(res, { [`varnish: ${name} ${label}`]: predicate }, TAGS);
  errorRate.add(!ok);
  if (!ok) recordFailure(res, `varnish ${name}`, [`varnish: ${name} ${label}`]);
  if (!ok && cfg.debug) console.warn(`[varnish] ${name}: ${label} failed (status ${res.status}, cache ${cacheState(res)})`);
  return ok;
}

const isHit = (r) => cacheState(r) === 'HIT';
const notHit = (r) => r.status < 500 && cacheState(r) !== 'HIT';

function fresh(path) {
  const sep = path.includes('?') ? '&' : '?';
  return url(`${path}${sep}${PREFIX}-vcl=${Date.now()}${exec.vu.idInTest}${Math.floor(Math.random() * 1e6)}`);
}

function fetch(target, name, headers) {
  return http.get(target, { headers: Object.assign(baseHeaders(), headers || {}), tags: Object.assign({ name: `Varnish ${name}` }, TAGS) });
}

function categoryPath(data) {
  return data.categories && data.categories.length ? data.categories[0].url : '';
}

// Guest pages are cached, and a different X-Magento-Vary value gets its own cache entry.
function pageCaching(data) {
  const page = fresh(categoryPath(data));
  expect(fetch(page, 'category'), 'category', (r) => r.status === 200 && cacheState(r) === 'MISS', 'first request is MISS');
  expect(fetch(page, 'category'), 'category', isHit, 'second request is HIT');
  const fakeVary = { Cookie: 'X-Magento-Vary=0123456789abcdef0123456789abcdef01234567' };
  expect(fetch(page, 'category vary', fakeVary), 'X-Magento-Vary', notHit, 'cookie gets its own cache entry (not the guest HIT)');
}

// Customer and private pages never come from the cache.
function privatePages() {
  for (const [path, name] of [['customer/account/login/', 'customer login page'], ['checkout/cart/', 'cart page']]) {
    fetch(url(path), name);
    expect(fetch(url(path), name), name, notHit, 'is never a HIT');
  }
  const section = url(`customer/section/load/?sections=cart&force_new_section_timestamp=true&_=${Date.now()}`);
  fetch(section, 'section load', { 'X-Requested-With': 'XMLHttpRequest' });
  expect(fetch(section, 'section load', { 'X-Requested-With': 'XMLHttpRequest' }), 'customer/section/load', notHit, 'is never a HIT');
}

// A logged-in customer (X-Magento-Vary set at login) must not be served the guest copy.
function loggedInCustomer(data) {
  if (!data.customers || !data.customers.length) return;
  http.cookieJar().clear(cfg.baseUrl);
  const page = fresh(categoryPath(data));
  fetch(page, 'category guest');
  expect(fetch(page, 'category guest'), 'guest category', isHit, 'is cached for guests');
  const session = customerLogin(data);
  if (session.ok) {
    expect(fetch(page, 'category customer'), 'logged-in customer', notHit, 'does not get the guest HIT');
    customerLogout();
  }
  http.cookieJar().clear(cfg.baseUrl);
}

// GraphQL GET: guests cached per X-Magento-Cache-Id; customers passed without a cache id,
// cached under their own id (plus the "Authorized" marker) with one.
function graphqlCaching(data) {
  const query = encodeURIComponent('{ storeConfig { store_code base_currency_code } }');
  const target = () => fresh(`graphql?query=${query}`);
  const json = { 'Content-Type': 'application/json', Accept: 'application/json' };

  const guestUrl = target();
  const first = fetch(guestUrl, 'graphql guest', json);
  expect(first, 'graphql guest', (r) => r.status === 200 && Boolean(r.headers['X-Magento-Cache-Id']), 'returns X-Magento-Cache-Id');
  expect(fetch(guestUrl, 'graphql guest', json), 'graphql guest', isHit, 'second request is HIT');

  if (!data.customers || !data.customers.length) return;
  const token = customerToken(data);
  if (!token) return;
  const auth = Object.assign({ Authorization: `Bearer ${token}` }, json);

  const noIdUrl = target();
  const noId = fetch(noIdUrl, 'graphql customer', auth);
  expect(fetch(noIdUrl, 'graphql customer', auth), 'graphql customer without cache id', notHit, 'is passed (never a HIT)');

  const customerId = noId.headers['X-Magento-Cache-Id'];
  if (!expect(noId, 'graphql customer', () => Boolean(customerId), 'returns its own X-Magento-Cache-Id')) return;
  const withIdUrl = target();
  const withId = Object.assign({ 'X-Magento-Cache-Id': customerId }, auth);
  expect(fetch(withIdUrl, 'graphql customer cached', withId), 'graphql customer with cache id', notHit, 'first request is not the guest copy');
  expect(fetch(withIdUrl, 'graphql customer cached', withId), 'graphql customer with cache id', isHit, 'second request is HIT');
}

// Static assets are cached and keep their long browser cache lifetime.
function staticAssets() {
  const home = http.get(url(''), { headers: baseHeaders(), tags: Object.assign({ name: 'Varnish home' }, TAGS) });
  const css = match(home.body, /href="(https?:\/\/[^"]+\/static\/[^"]+\.css)"/);
  if (!css) return;
  fetch(css, 'static');
  const res = fetch(css, 'static');
  expect(res, 'static asset', isHit, 'second request is HIT');
  expect(res, 'static asset', (r) => !/max-age=120\b/.test(r.headers['Cache-Control'] || ''), 'keeps its own Cache-Control');
}

export function varnishChecks(data) {
  group('Varnish cache behaviour', () => {
    http.cookieJar().clear(cfg.baseUrl);
    pageCaching(data);
    privatePages();
    loggedInCustomer(data);
    graphqlCaching(data);
    staticAssets();
  });
}
