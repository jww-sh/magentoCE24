// PROFILE=cleanup: remove what the benchmark created (everything is tagged k6mlt-…).
//
// Every REST search match is re-checked client-side with startsWith('k6mlt-')
// before anything is touched.
//
// Orders cannot be deleted through Magento Open Source's API, so k6 orders are
// cancelled here, the stock their shipments took is returned through MSI, and
// testing/k6/cleanup-orders.php deletes them afterwards with Magento's own
// repositories (plus carts, reservations, visitors, reports and caches).
// Customers, k6mlt-simple products and admin users are kept by default because the
// next run reuses them; CLEANUP_CUSTOMERS=1 / CLEANUP_ADMINS=1 remove them too.
import { cfg, PREFIX } from '../lib/config.js';
import { restToken, rest, searchCriteria } from '../lib/bootstrap.js';
import { AdminClient } from '../lib/admin.js';
import { match } from '../lib/http.js';

function ours(value) {
  return String(value || '').startsWith(`${PREFIX}-`);
}

function removeAll(token, label, searchPath, field, value, deletePath) {
  const found = rest(token, 'GET', `${searchPath}?${searchCriteria(field, value)}`, null, `Cleanup search ${label}`);
  const items = ((found.body && found.body.items) || []).filter((item) => ours(item[field]));
  let removed = 0;
  for (const item of items) {
    const r = rest(token, 'DELETE', deletePath(item), null, `Cleanup delete ${label}`);
    if (r.res.status === 200) removed++;
    else console.warn(`Could not delete ${label} ${item[field]}: ${r.res.status}`);
  }
  console.log(`${label}: removed ${removed}/${items.length}`);
}

// Admin user grid rows carry <td data-column="user_id"> N </td> and
// <td data-column="username"> name </td>. Each row is parsed on its own so an id
// can never be paired with another row's username, and the edit page is checked
// again before deleting.
function k6AdminUsers(body) {
  const users = [];
  for (const row of body.split(/<tr\b/i).slice(1)) {
    const id = match(row, /data-column="user_id"[^>]*>\s*(\d+)\s*</);
    const username = match(row, /data-column="username"[^>]*>\s*([^<\s]+)\s*</);
    if (id && parseInt(id, 10) > 0 && new RegExp(`^${PREFIX}-admin-\\d+$`).test(username || '')) users.push({ id, username });
  }
  return users;
}

function removeAdminUsers() {
  const admin = new AdminClient(cfg.adminUser, cfg.adminPassword);
  if (!admin.login()) return;
  const list = admin.get('admin/user/index', 'Cleanup admin users', { params: 'limit/200/' });
  const users = k6AdminUsers(list.body || '');
  let removed = 0;
  for (const u of users) {
    const edit = admin.get('admin/user/edit', 'Cleanup edit admin user', { params: `user_id/${u.id}/` });
    const shown = match(edit.body, /name="username"[^>]*value="([^"]*)"/) || match(edit.body, /value="([^"]*)"[^>]*name="username"/);
    if (shown !== u.username || u.username === cfg.adminUser) {
      console.warn(`Skipping user_id ${u.id}: edit page shows "${shown}", expected ${u.username}`);
      continue;
    }
    const r = admin.post(
      'admin/user/delete',
      { user_id: u.id, current_password: cfg.adminPassword },
      'Cleanup delete admin user',
      { expect: ['You deleted the user.'] }
    );
    if ((r.body || '').includes('You deleted the user.')) removed++;
  }
  admin.logout();
  console.log(`admin users: removed ${removed}/${users.length}`);
}

const STOCK_MARKER = 'k6: shipped stock restored';

// Give back what k6 shipments took from the default source (MSI keeps the legacy
// stock table and the stock index in sync). Each order is marked with a comment
// once done, so running cleanup again never adds the stock twice.
function restoreShippedStock(token, orders) {
  let units = 0;
  let done = 0;
  for (const o of orders) {
    const order = rest(token, 'GET', `orders/${o.entity_id}`, null, 'Cleanup get order').body;
    if (!order || (order.status_histories || []).some((h) => (h.comment || '').includes(STOCK_MARKER))) continue;
    const shipments = rest(token, 'GET', `shipments?${searchCriteria('order_id', o.entity_id, 'eq')}`, null, 'Cleanup get shipments');
    const shipped = {};
    for (const s of (shipments.body && shipments.body.items) || []) {
      for (const item of s.items || []) {
        if (!cfg.cleanupStockSkip.includes(item.sku)) shipped[item.sku] = (shipped[item.sku] || 0) + Number(item.qty);
      }
    }
    const skus = Object.keys(shipped);
    if (skus.length) {
      const current = rest(token, 'GET', `inventory/source-items?${searchCriteria('sku', skus.join(','), 'in')}`, null, 'Cleanup get source items');
      const sourceItems = ((current.body && current.body.items) || [])
        .filter((si) => si.source_code === 'default')
        .map((si) => ({ sku: si.sku, source_code: 'default', quantity: Number(si.quantity) + shipped[si.sku], status: 1 }));
      const saved = rest(token, 'POST', 'inventory/source-items', { sourceItems }, 'Cleanup restore stock');
      if (saved.res.status !== 200) {
        console.warn(`Could not restore stock for order ${o.increment_id}: ${saved.res.status} ${saved.res.body}`);
        continue;
      }
      units += sourceItems.reduce((sum, si) => sum + shipped[si.sku], 0);
    }
    rest(
      token,
      'POST',
      `orders/${o.entity_id}/comments`,
      { statusHistory: { comment: STOCK_MARKER, is_customer_notified: 0, is_visible_on_front: 0, parent_id: o.entity_id, status: order.status } },
      'Cleanup mark order'
    );
    done++;
  }
  console.log(`stock: ${units} shipped units returned to stock from ${done} orders`);
}

// Marketing > SEO & Search > Search Terms: mass delete the terms k6 searched for.
function removeSearchTerms() {
  const admin = new AdminClient(cfg.adminUser, cfg.adminPassword);
  if (!admin.login()) return;
  const grid = admin.get('search/term/index', 'Cleanup search terms', { params: 'limit/200/' });
  const terms = new Set(cfg.searchTerms.map((t) => t.trim().toLowerCase()));
  const ids = [];
  for (const row of (grid.body || '').split(/<tr\b/i).slice(1)) {
    const id = match(row, /name="search"[^>]*value="(\d+)"/);
    const text = match(row, /data-column="search_query"[^>]*>\s*([^<]*?)\s*</);
    if (id && text && terms.has(text.toLowerCase())) ids.push(id);
  }
  if (ids.length) {
    const body = {};
    ids.forEach((id, i) => (body[`search[${i}]`] = id));
    admin.post('search/term/massDelete', body, 'Cleanup delete search terms', { expect: [/deleted/i] });
  }
  admin.logout();
  console.log(`search terms: removed ${ids.length}`);
}

export function cleanup() {
  const token = restToken();

  const orders = rest(token, 'GET', `orders?${searchCriteria('customer_email', `${PREFIX}-%`)}`, null, 'Cleanup search orders');
  const all = ((orders.body && orders.body.items) || []).filter((o) => ours(o.customer_email));
  let cancelled = 0;
  for (const o of all) {
    if (['canceled', 'closed', 'complete'].includes(o.status)) continue;
    const r = rest(token, 'POST', `orders/${o.entity_id}/cancel`, null, 'Cleanup cancel order');
    if (r.res.status === 200 && r.body === true) cancelled++;
  }
  console.log(`orders: ${all.length} k6 orders found, ${cancelled} cancelled (delete them with cleanup-orders.php)`);
  restoreShippedStock(token, all);
  removeSearchTerms();

  removeAll(token, 'products', 'products', 'sku', `${PREFIX}-product-%`, (p) => `products/${encodeURIComponent(p.sku)}`);
  removeAll(token, 'cms pages', 'cmsPage/search', 'title', `${PREFIX}-%`, (p) => `cmsPage/${p.id}`);
  removeAll(token, 'cart rules', 'salesRules/search', 'name', `${PREFIX}-%`, (r) => `salesRules/${r.rule_id}`);
  removeAll(token, 'categories', 'categories/list', 'name', `${PREFIX}-%`, (c) => `categories/${c.id}`);

  if (cfg.cleanupCustomers) {
    removeAll(token, 'customers', 'customers/search', 'email', `${PREFIX}-%`, (c) => `customers/${c.id}`);
    removeAll(token, 'k6 products', 'products', 'sku', `${PREFIX}-simple-%`, (p) => `products/${encodeURIComponent(p.sku)}`);
  }

  if (cfg.cleanupAdmins) removeAdminUsers();
}
