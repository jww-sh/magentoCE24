// PROFILE=cleanup: remove what the benchmark created (everything is k6_-prefixed).
//
// Orders cannot be deleted in Magento Open Source without an extension, so k6
// orders are cancelled instead (frees reserved stock). Customers and admin users
// are kept by default because the next run reuses them.
import { cfg, PREFIX } from '../lib/config.js';
import { restToken, rest, searchCriteria } from '../lib/bootstrap.js';
import { AdminClient } from '../lib/admin.js';

function removeAll(token, label, searchPath, field, value, deletePath) {
  const found = rest(token, 'GET', `${searchPath}?${searchCriteria(field, value)}`, null, `Cleanup search ${label}`);
  const items = (found.body && found.body.items) || [];
  let removed = 0;
  for (const item of items) {
    const r = rest(token, 'DELETE', deletePath(item), null, `Cleanup delete ${label}`);
    if (r.res.status === 200) removed++;
    else console.warn(`Could not delete ${label} ${JSON.stringify(item.id || item.sku)}: ${r.res.status}`);
  }
  console.log(`${label}: removed ${removed}/${items.length}`);
}

export function cleanup() {
  const token = restToken();

  const orders = rest(token, 'GET', `orders?${searchCriteria('customer_email', `${PREFIX}%`)}`, null, 'Cleanup search orders');
  let cancelled = 0;
  const all = (orders.body && orders.body.items) || [];
  for (const o of all) {
    if (['canceled', 'closed', 'complete'].includes(o.status)) continue;
    const r = rest(token, 'POST', `orders/${o.entity_id}/cancel`, null, 'Cleanup cancel order');
    if (r.res.status === 200 && r.body === true) cancelled++;
  }
  console.log(`orders: ${all.length} k6 orders found, ${cancelled} cancelled (the rest are invoiced/closed)`);

  removeAll(token, 'products', 'products', 'sku', `${PREFIX}product_%`, (p) => `products/${encodeURIComponent(p.sku)}`);
  removeAll(token, 'cms pages', 'cmsPage/search', 'title', `${PREFIX}%`, (p) => `cmsPage/${p.id}`);
  removeAll(token, 'cart rules', 'salesRules/search', 'name', `${PREFIX}%`, (r) => `salesRules/${r.rule_id}`);
  removeAll(token, 'categories', 'categories/list', 'name', `${PREFIX}%`, (c) => `categories/${c.id}`);

  if (cfg.cleanupCustomers) {
    removeAll(token, 'customers', 'customers/search', 'email', `${PREFIX}%`, (c) => `customers/${c.id}`);
    removeAll(token, 'k6 products', 'products', 'sku', `${PREFIX}simple_%`, (p) => `products/${encodeURIComponent(p.sku)}`);
  }

  if (cfg.cleanupAdmins) {
    const admin = new AdminClient(cfg.adminUser, cfg.adminPassword);
    if (!admin.login()) return;
    const list = admin.get('admin/user/index', 'Cleanup admin users', { params: 'limit/200/' });
    const body = (list.body || '').replace(/\\\//g, '/');
    // user grid rows link to admin/user/edit/user_id/N/ — read id + username pairs
    const re = new RegExp(`admin/user/edit/user_id/(\\d+)/[^"]*"[\\s\\S]*?(${PREFIX}admin_\\d+)`, 'g');
    const ids = {};
    let m;
    while ((m = re.exec(body)) !== null) ids[m[2]] = m[1];
    let removed = 0;
    for (const username of Object.keys(ids)) {
      admin.get('admin/user/edit', 'Cleanup edit admin user', { params: `user_id/${ids[username]}/` });
      const r = admin.post(
        'admin/user/delete',
        { user_id: ids[username], current_password: cfg.adminPassword },
        'Cleanup delete admin user',
        { expect: ['You deleted the user.'] }
      );
      if ((r.body || '').includes('You deleted the user.')) removed++;
    }
    admin.logout();
    console.log(`admin users: removed ${removed}/${Object.keys(ids).length}`);
  }
}
