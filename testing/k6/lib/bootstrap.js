// setup()-time bootstrap: from the one ADMIN_USER/ADMIN_PASSWORD pair, make sure
// the test customers, admin users and k6-owned products exist. Idempotent, so
// every run reuses what previous runs created.
import http from 'k6/http';
import crypto from 'k6/crypto';
import { cfg, PREFIX, tagged, taggedEmail, EMAIL_DOMAIN } from './config.js';
import { baseHeaders, url, qs, match } from './http.js';
import { AdminClient } from './admin.js';

// Deterministic password for everything k6 creates, derived from the admin
// password so no second secret is needed. Satisfies Magento's customer (3 char
// classes, 8+) and admin (letters + digits, 7+) password rules.
export function derivedPassword() {
  return `K6a!${crypto.sha256(`${cfg.adminPassword}:k6`, 'hex').slice(0, 20)}`;
}

// Password for an admin user from setup data (the main admin when accounts are shared).
export function adminPasswordFor(username) {
  return username === cfg.adminUser ? cfg.adminPassword : derivedPassword();
}

export function restToken() {
  const res = http.post(
    url('rest/V1/integration/admin/token'),
    JSON.stringify({ username: cfg.adminUser, password: cfg.adminPassword }),
    {
      // Magento REST picks XML for a browser Accept header, so ask for JSON explicitly
      headers: Object.assign(baseHeaders(), { 'Content-Type': 'application/json', Accept: 'application/json' }),
      tags: { name: 'SetUp - Admin Token' },
    }
  );
  if (res.status === 0) {
    throw new Error(`Cannot reach ${cfg.baseUrl} (${res.error || 'network error'}); check the URL variable`);
  }
  if (res.status !== 200) {
    throw new Error(
      `Admin REST token failed (${res.status}): ${res.body}. Is twofactorauth/general/enable_for_api_token_generation=0?`
    );
  }
  return res.json();
}

export function rest(token, method, path, payload, name) {
  const res = http.request(method, url(`rest/default/V1/${path}`), payload ? JSON.stringify(payload) : null, {
    headers: Object.assign(baseHeaders(), {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    }),
    tags: { name: name || `REST ${method} ${path.split('/')[0]}` },
  });
  let body = null;
  try {
    body = res.json();
  } catch (e) {
    body = null;
  }
  return { res, body };
}

export function searchCriteria(field, value, condition, pageSize) {
  return qs({
    'searchCriteria[filterGroups][0][filters][0][field]': field,
    'searchCriteria[filterGroups][0][filters][0][value]': value,
    'searchCriteria[filterGroups][0][filters][0][conditionType]': condition || 'like',
    'searchCriteria[pageSize]': pageSize || 500,
  });
}

function ensureCustomers(token, password, regionId) {
  const found = rest(token, 'GET', `customers/search?${searchCriteria('email', `${PREFIX}-user-%@${EMAIL_DOMAIN}`)}`);
  const existing = {};
  for (const c of (found.body && found.body.items) || []) existing[c.email] = c.id;

  const customers = [];
  let created = 0;
  for (let i = 1; i <= cfg.customerCount; i++) {
    const email = taggedEmail('user', i);
    if (existing[email]) {
      customers.push({ email, id: existing[email] });
      continue;
    }
    const a = cfg.address;
    const address = {
      firstname: 'K6',
      lastname: `User${i}`,
      street: [a.street],
      city: a.city,
      postcode: a.postcode,
      telephone: a.telephone,
      country_id: a.countryId,
      default_billing: true,
      default_shipping: true,
    };
    if (regionId) address.region_id = regionId;
    const r = rest(
      token,
      'POST',
      'customers',
      {
        customer: { email, firstname: 'K6', lastname: `User${i}`, website_id: 1, group_id: 1, addresses: [address] },
        password,
      },
      'SetUp - Create Customer'
    );
    if (r.res.status === 200 && r.body) {
      customers.push({ email, id: r.body.id });
      created++;
    } else {
      console.error(`Could not create ${email}: ${r.res.status} ${r.res.body}`);
    }
  }
  console.log(`Customers: ${customers.length} available (${created} created)`);
  return customers;
}

// Products that admin "edit product" flows are allowed to modify. Not visible
// on the storefront (visibility 1) so shoppers never see them.
function ensureProducts(token, count) {
  const found = rest(token, 'GET', `products?${searchCriteria('sku', `${PREFIX}-simple-%`)}`);
  const existing = {};
  for (const p of (found.body && found.body.items) || []) existing[p.sku] = p.id;

  const products = [];
  for (let i = 1; i <= count; i++) {
    const sku = tagged('simple', i);
    if (existing[sku]) {
      products.push({ sku, id: existing[sku] });
      continue;
    }
    const r = rest(
      token,
      'POST',
      'products',
      {
        product: {
          sku,
          name: sku,
          attribute_set_id: 4,
          price: 10,
          status: 1,
          visibility: 1,
          type_id: 'simple',
          weight: 1,
          extension_attributes: { website_ids: [1], stock_item: { qty: 100000, is_in_stock: true } },
          custom_attributes: [{ attribute_code: 'url_key', value: sku }],
        },
      },
      'SetUp - Create Product'
    );
    if (r.res.status === 200 && r.body) products.push({ sku, id: r.body.id });
    else console.error(`Could not create product ${sku}: ${r.res.status} ${r.res.body}`);
  }
  return products;
}

// Magento allows one session per admin user (admin_account_sharing=0), so each
// admin VU uses its own k6mlt-admin-<VU id> user, created through the admin UI (there
// is no REST endpoint for admin users). Called by setup() with no names to check the
// main admin's access, and by each admin VU for its own user on first use.
export function ensureAdminUsers(usernames) {
  const password = derivedPassword();
  const users = usernames.map((username) => ({ username, password }));

  const admin = new AdminClient(cfg.adminUser, cfg.adminPassword);
  if (!admin.login()) throw new Error('Main admin login failed; check ADMIN_USER/ADMIN_PASSWORD and that admin 2FA is disabled');
  if (!admin.hasKey('admin/user/index')) {
    throw new Error(`${cfg.adminUser} cannot see System > Permissions > All Users; it needs the Administrators role`);
  }
  const list = admin.get('admin/user/index', 'SetUp - Admin Users', { params: 'limit/200/' });
  const existing = new Set((list.body || '').match(new RegExp(`${PREFIX}-admin-\\d+`, 'g')) || []);

  let created = 0;
  for (const u of users) {
    if (existing.has(u.username)) continue;
    admin.get('admin/user/new', 'SetUp - New Admin User');
    // Never send user_id for a new user: Magento treats '' as an existing id,
    // runs an UPDATE instead of an INSERT and then clears roles for user_id 0,
    // which deletes the Administrators group role.
    const res = admin.post(
      'admin/user/save',
      {
        username: u.username,
        firstname: 'K6',
        lastname: u.username,
        email: `${u.username}@${EMAIL_DOMAIN}`,
        password: u.password,
        password_confirmation: u.password,
        interface_locale: 'en_US',
        is_active: '1',
        current_password: cfg.adminPassword,
        'roles[]': cfg.adminRoleId,
      },
      'SetUp - Save Admin User',
      { expect: ['You saved the user.'] }
    );
    if (!(res.body || '').includes('You saved the user.')) {
      console.error(`Could not create admin ${u.username}: ${match(res.body, /messages-message-error"[^>]*>\s*([^<]+)/)}`);
    }
  }
  // Trust the user grid, not the success message
  const after = admin.get('admin/user/index', 'SetUp - Admin Users', { params: 'limit/200/' });
  const present = new Set((after.body || '').match(new RegExp(`${PREFIX}-admin-\\d+`, 'g')) || []);
  admin.logout();
  const missing = users.filter((u) => !present.has(u.username)).map((u) => u.username);
  if (missing.length) throw new Error(`Admin users missing after save: ${missing.join(', ')}`);
  created = users.filter((u) => !existing.has(u.username)).length;
  if (users.length) console.log(`Admin users: ${users.map((u) => u.username).join(', ')} (${created} created)`);
  return users;
}

// Fetch every non-k6 simple SKU from the admin API regardless of stock status.
// discover() only surfaces IN_STOCK products, so products that hit 0 in a prior
// run would be invisible to it and never get reset — this avoids that blind spot.
function fetchAllSimpleSkus(token) {
  const skus = [];
  const pageSize = 500;
  let page = 1;
  let pages = 1;
  while (page <= pages) {
    const q = qs({
      'searchCriteria[filterGroups][0][filters][0][field]': 'type_id',
      'searchCriteria[filterGroups][0][filters][0][value]': 'simple',
      'searchCriteria[filterGroups][0][filters][0][conditionType]': 'eq',
      'searchCriteria[filterGroups][1][filters][0][field]': 'sku',
      'searchCriteria[filterGroups][1][filters][0][value]': `${PREFIX}-%`,
      'searchCriteria[filterGroups][1][filters][0][conditionType]': 'nlike',
      'searchCriteria[pageSize]': pageSize,
      'searchCriteria[currentPage]': page,
      fields: 'items[sku],total_count',
    });
    const r = rest(token, 'GET', `products?${q}`, null, 'SetUp - All Simple SKUs');
    if (!r.body || !r.body.items) {
      console.warn(`fetchAllSimpleSkus: page ${page} failed (${r.res.status})`);
      break;
    }
    for (const p of r.body.items) skus.push(p.sku);
    pages = Math.ceil((r.body.total_count || 0) / pageSize);
    page++;
  }
  return skus;
}

function resetCatalogStock(token, skus) {
  if (!skus || !skus.length) return;
  const qty = 100000;
  const chunkSize = 100;
  let reset = 0;
  for (let i = 0; i < skus.length; i += chunkSize) {
    const sourceItems = skus.slice(i, i + chunkSize).map((sku) => ({ sku, source_code: 'default', quantity: qty, status: 1 }));
    const r = rest(token, 'POST', 'inventory/source-items', { sourceItems }, 'SetUp - Reset Stock');
    if (r.res.status === 200) reset += sourceItems.length;
    else console.warn(`Stock reset failed for chunk starting at ${skus[i]}: ${r.res.status}`);
  }
  console.log(`Stock: reset ${reset}/${skus.length} catalog products to ${qty} units`);
}

// Saleable qty = physical_qty - sum(reservations). Orders placed in prior runs leave
// positive reservations behind; without compensating them, saleable qty drifts below
// zero even after the source-item reset. This appends negative reservations to cancel
// all existing positives, restoring full saleable qty.
function compensateReservations(token, skus) {
  if (!skus || !skus.length) return;
  const skuSet = new Set(skus);
  // Fetch all open reservations for catalog SKUs
  const pageSize = 500;
  let page = 1;
  let pages = 1;
  const totals = {}; // sku -> net reservation quantity
  while (page <= pages) {
    const q = qs({
      'searchCriteria[pageSize]': pageSize,
      'searchCriteria[currentPage]': page,
    });
    const r = rest(token, 'GET', `inventory/reservations?${q}`, null, 'SetUp - Fetch Reservations');
    if (!r.body || !r.body.items) break;
    for (const item of r.body.items) {
      if (!skuSet.has(item.sku)) continue;
      totals[item.sku] = (totals[item.sku] || 0) + item.quantity;
    }
    pages = Math.ceil((r.body.total_count || 0) / pageSize);
    page++;
  }
  // Post compensation reservations for any SKU with a net positive total
  const compensations = Object.entries(totals)
    .filter(([, q]) => q > 0)
    .map(([sku, q]) => ({ sku, quantity: -q, metadata: { event_type: 'k6_reset', object_type: 'order', object_id: '0', object_increment_id: '0' } }));
  if (!compensations.length) {
    console.log('Reservations: nothing to compensate');
    return;
  }
  const chunkSize = 100;
  let compensated = 0;
  for (let i = 0; i < compensations.length; i += chunkSize) {
    const chunk = compensations.slice(i, i + chunkSize);
    const r = rest(token, 'POST', 'inventory/reservations', { reservations: chunk }, 'SetUp - Compensate Reservations');
    if (r.res.status === 200) compensated += chunk.length;
    else console.warn(`Reservation compensation failed for chunk at ${i}: ${r.res.status} ${r.res.body}`);
  }
  console.log(`Reservations: compensated ${compensated}/${compensations.length} SKUs`);
}

export function bootstrap(regionId, needAdminUsers, catalogSkus) {
  const token = restToken();
  const password = derivedPassword();
  const customers = ensureCustomers(token, password, regionId);
  const products = ensureProducts(token, Math.max(5, cfg.adminVus * 2));
  // Fetch all simple SKUs directly so out-of-stock products from prior runs are included.
  // catalogSkus (from discover) only has IN_STOCK products and would miss them.
  const allSkus = fetchAllSimpleSkus(token);
  resetCatalogStock(token, allSkus.length ? allSkus : catalogSkus);
  compensateReservations(token, allSkus.length ? allSkus : catalogSkus);
  // admin: null (no admin flows), { shared: true } (every VU uses ADMIN_USER) or
  // { perVu: true } (each admin VU creates/uses k6mlt-admin-<VU id> on first use).
  let admin = null;
  if (needAdminUsers) {
    if (cfg.adminShareAccount) {
      admin = { shared: true };
    } else {
      ensureAdminUsers([]); // fail early if the main admin can't manage users
      admin = { perVu: true };
    }
  }
  // No passwords in the returned data: k6 writes setup data into summary.json.
  // VUs derive them again with derivedPassword() / adminPasswordFor().
  return { customers, admin, k6Products: products };
}
