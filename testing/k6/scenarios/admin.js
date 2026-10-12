// Admin flows from the JMX "Combined Benchmark Pool" [C] Admin * controllers.
//
// Production-safety deviations from the JMX:
//  - edit product only touches hidden k6mlt-simple-N products
//  - customer management only touches k6mlt- customers
//  - edit order / returns only touch pending orders placed by k6mlt- emails
//  - created products, CMS pages, categories and cart rules are k6mlt-named and
//    created inactive / not visible, so shoppers never see them
// Secret URL keys are harvested from pages (see lib/admin.js); because a key
// only depends on route/controller/action, a key taken from any grid row's
// link is reused with the k6-owned entity id.
import exec from 'k6/execution';
import { group } from 'k6';
import { cfg, mix, PREFIX, tagged } from '../lib/config.js';
import { AdminClient } from '../lib/admin.js';
import { adminPasswordFor, ensureAdminUsers } from '../lib/bootstrap.js';
import { think, pick, weighted, match, uniq } from '../lib/http.js';

let client = null;

function adminFor(data) {
  if (!client) {
    // One admin user per VU: VU ids aren't contiguous per scenario, so mapping a fixed
    // pool by id modulo let two VUs share a user and log each other out.
    const username = data.admin.shared ? cfg.adminUser : tagged('admin', exec.vu.idInTest);
    if (!data.admin.shared) ensureAdminUsers([username]);
    client = new AdminClient(username, adminPasswordFor(username));
  }
  return client;
}

function session(data, name, fn) {
  group(`Admin ${name}`, () => {
    const admin = adminFor(data);
    if (!admin.login()) return;
    think();
    try {
      fn(admin);
    } finally {
      admin.logout();
    }
  });
}

function skip(why) {
  if (cfg.debug) console.log(`[VU ${exec.vu.idInTest}] admin flow skipped: ${why}`);
}

function k6PendingOrders(admin) {
  const json = admin.grid(
    'sales_order_grid',
    {
      'filters[status]': 'pending',
      'paging[pageSize]': '200',
      'sorting[field]': 'increment_id',
      'sorting[direction]': 'desc',
    },
    'Admin Search Pending Orders'
  );
  return ((json && json.items) || []).filter((o) => String(o.customer_email || '').startsWith(`${PREFIX}-`));
}

function orderItemIds(body) {
  const ids = [];
  const re = /order_item_(\d+)_title/g;
  let m;
  while ((m = re.exec(body || '')) !== null) ids.push(m[1]);
  return [...new Set(ids)];
}

function invoice(admin, orderId, comment) {
  const start = admin.get('sales/order_invoice/start', 'Admin Invoice Start', {
    params: `order_id/${orderId}/`,
    expect: ['Invoice Totals'],
  });
  const body = { 'invoice[comment_text]': comment };
  for (const id of orderItemIds(start.body)) body[`invoice[items][${id}]`] = 1;
  return admin.post('sales/order_invoice/save', body, 'Admin Invoice Submit', {
    params: `order_id/${orderId}/`,
    expect: ['The invoice has been created'],
  });
}

function ship(admin, orderId, comment) {
  const start = admin.get('admin/order_shipment/start', 'Admin Shipment Start', {
    params: `order_id/${orderId}/`,
    expect: ['New Shipment'],
  });
  const body = { 'shipment[comment_text]': comment };
  for (const id of orderItemIds(start.body)) body[`shipment[items][${id}]`] = 1;
  return admin.post('admin/order_shipment/save', body, 'Admin Shipment Submit', {
    params: `order_id/${orderId}/`,
    expect: ['The shipment has been created'],
  });
}

// Opens a pending k6 order; returns its entity id or null.
function openK6Order(admin) {
  admin.get('sales/order/index', 'Admin Orders Page', { expect: ['Create New Order'] });
  const orders = k6PendingOrders(admin);
  if (orders.length === 0) return null;
  const order = pick(orders);
  const view = admin.get('sales/order/view', 'Admin Open Order', {
    params: `order_id/${order.entity_id}/`,
    expect: [`#${order.increment_id}`],
  });
  // never mutate an order that isn't ours
  return (view.body || '').includes(`${PREFIX}-`) ? order.entity_id : null;
}

function cms(admin) {
  admin.get('cms/page/index', 'Admin CMS Landing Page');
  think();
  admin.get('cms/page/new', 'Admin CMS Create New');
  think();
  const id = uniq(`${PREFIX}-cms-`);
  admin.post(
    'cms/page/save',
    {
      content: `<p>CMS Content ${id}</p>`,
      content_heading: '',
      identifier: id,
      is_active: '0',
      layout_update_xml: '',
      meta_description: '',
      meta_keywords: '',
      meta_title: '',
      page_id: '',
      page_layout: '1column',
      'store_id[0]': '0',
      title: id,
      website_root: '0',
    },
    'Admin CMS Save',
    { expect: ['You saved the page.'] }
  );
}

const GRIDS = {
  product_grid: {
    landing: 'catalog/product/index',
    namespace: 'product_listing',
    filterField: 'name',
    filterText: () => pick(cfg.searchTerms).trim(),
    sorts: ['name', 'price'],
  },
  order_grid: {
    landing: 'sales/order/index',
    namespace: 'sales_order_grid',
    filterField: 'status',
    filterText: () => 'pending',
    sorts: ['increment_id', 'grand_total'],
  },
  customer_grid: {
    landing: 'customer/index/index',
    namespace: 'customer_listing',
    filterField: 'email',
    filterText: () => PREFIX,
    sorts: ['name', 'email'],
  },
};

function browseGrid(admin, kind) {
  const g = GRIDS[kind];
  const label = kind.replace('_grid', '');
  admin.get(g.landing, `Admin ${label} grid page`);
  const all = admin.grid(g.namespace, {}, `Admin ${label} grid`);
  const pages = Math.max(1, Math.round(((all && all.totalRecords) || 0) / 20));
  admin.grid(g.namespace, { 'paging[current]': String(1 + Math.floor(Math.random() * pages)) }, `Admin ${label} grid page N`);
  const text = g.filterText();
  for (const field of g.sorts) {
    for (const dir of ['asc', 'desc']) {
      admin.grid(
        g.namespace,
        { [`filters[${g.filterField}]`]: text, 'sorting[field]': field, 'sorting[direction]': dir },
        `Admin ${label} grid filter + sort`
      );
    }
  }
}

function productFields(name, sku, price, extra) {
  return Object.assign(
    {
      ajax: 'true',
      isAjax: 'true',
      'product[name]': name,
      'product[sku]': sku,
      'product[price]': String(price),
      'product[tax_class_id]': '2',
      'product[quantity_and_stock_status][qty]': '1000',
      'product[quantity_and_stock_status][is_in_stock]': '1',
      'product[weight]': '1',
      'product[product_has_weight]': '1',
      'product[status]': '1',
      'product[visibility]': '1',
      'product[website_ids][]': '1',
      'product[url_key]': sku,
      'product[description]': `<p>${name} description</p>`,
      'product[stock_data][use_config_manage_stock]': '1',
      'product[stock_data][qty]': '1000',
      'product[stock_data][is_in_stock]': '1',
      affect_configurable_product_attributes: '1',
      'product[configurable_variations]': '',
    },
    extra || {}
  );
}

function createProduct(admin) {
  admin.get('catalog/product/index', 'Admin Catalog Product', { expect: ['records found'] });
  think();
  admin.get('catalog/product/new', 'Admin New Simple Product', { params: 'set/4/type/simple/', expect: ['New Product'] });
  think();
  const sku = uniq(`${PREFIX}-product-`);
  const fields = productFields(sku, sku, 42);
  admin.post('catalog/product/validate', fields, 'Admin New Product Validate', {
    params: 'set/4/',
    ajax: true,
    expect: ['"error":false'],
  });
  admin.post('catalog/product/save', fields, 'Admin New Product Save', {
    params: 'set/4/type/simple/back/edit/active_tab/product-details/',
    expect: ['You saved the product'],
  });
}

// Only k6mlt-simple-N products: an admin product save treats every field missing
// from the request as cleared (categories, stock) and a simple product without
// product_has_weight is converted to virtual, so sample catalog products can't
// be "re-saved unchanged" without replaying their whole form.
function editProduct(admin, data) {
  if (!data.k6Products.length) return skip('no k6 products');
  admin.get('catalog/product/index', 'Admin Catalog Product');
  // harvests the catalog/product/edit key from the grid row actions
  admin.grid('product_listing', { 'paging[pageSize]': '5' }, 'Admin product grid');
  const p = pick(data.k6Products);
  admin.get('catalog/product/edit', 'Admin Edit Product', { params: `id/${p.id}/`, expect: [p.sku] });
  think();
  const fields = productFields(p.sku, p.sku, (10 + Math.random() * 90).toFixed(2));
  admin.post('catalog/product/validate', fields, 'Admin Edit Product Validate', {
    params: `id/${p.id}/`,
    ajax: true,
    expect: [/"error":(false|0)/],
  });
  admin.post('catalog/product/save', fields, 'Admin Edit Product Save', {
    params: `id/${p.id}/back/edit/active_tab/product-details/`,
    expect: ['You saved the product'],
  });
}

function createOrder(admin, data) {
  const customer = pick(data.customers);
  admin.get('sales/order/index', 'Admin Orders Page');
  admin.get('sales/order_create/start', 'Admin Start Order');
  think();
  const simple1 = pick(data.simples);
  const simple2 = pick(data.simples);
  const conf = pick(data.configurables);
  const items = {
    [`item[${simple1.id}][qty]`]: '1',
    [`item[${simple2.id}][qty]`]: '1',
    [`item[${conf.id}][qty]`]: '1',
  };
  for (const attrId of Object.keys(conf.superAttributes)) {
    items[`item[${conf.id}][super_attribute][${attrId}]`] = String(conf.superAttributes[attrId]);
  }
  admin.post(
    'sales/order_create/loadBlock',
    Object.assign(items, {
      customer_id: String(customer.id),
      store_id: '1',
      currency_id: '',
      'payment[method]': cfg.paymentMethod,
      reset_shipping: '1',
      json: '1',
      as_js_varname: 'iFrameResponse',
    }),
    'Admin Order Add Products',
    { params: 'block/search,items,shipping_method,totals,giftmessage,billing_method/', query: 'isAjax=true', ajax: true }
  );
  admin.post(
    'sales/order_create/loadBlock',
    {
      collect_shipping_rates: '1',
      customer_id: String(customer.id),
      store_id: '1',
      currency_id: 'false',
      'payment[method]': cfg.paymentMethod,
      json: 'true',
    },
    'Admin Order Collect Shipping Rates',
    { params: 'block/shipping_method,totals/', query: 'isAjax=true', ajax: true, expect: ['shipping_method'] }
  );
  admin.get('sales/order_create/index', 'Admin Filled Order Page', { expect: ['Submit Order'] });
  think();
  const a = cfg.address;
  const save = admin.post(
    'sales/order_create/save',
    {
      'order[currency]': 'USD',
      'order[account][group_id]': '1',
      'order[account][email]': customer.email,
      'order[billing_address][customer_address_id]': '',
      'order[billing_address][firstname]': 'K6',
      'order[billing_address][lastname]': 'Admin Order',
      'order[billing_address][street][0]': a.street,
      'order[billing_address][city]': a.city,
      'order[billing_address][country_id]': a.countryId,
      'order[billing_address][region_id]': data.regionId ? String(data.regionId) : '',
      'order[billing_address][region]': data.regionId ? '' : a.region,
      'order[billing_address][postcode]': a.postcode,
      'order[billing_address][telephone]': a.telephone,
      shipping_same_as_billing: 'on',
      'payment[method]': cfg.paymentMethod,
      'order[shipping_method]': `${cfg.shippingCarrier}_${cfg.shippingMethod}`,
      'order[comment][customer_note]': '',
      'order[comment][customer_note_notify]': '0',
      'order[send_confirmation]': '0',
    },
    'Admin Save Order',
    { expect: ['You created the order.'] }
  );
  const orderId = match(save.url, /order_id\/(\d+)/) || match(save.body, /sales\/order\/(?:index|view)\/order_id\/(\d+)\//);
  if (!orderId) return;
  think();
  invoice(admin, orderId, '');
  ship(admin, orderId, '');
}

function editOrder(admin) {
  const orderId = openK6Order(admin);
  if (!orderId) return skip('no pending k6 orders');
  think();
  admin.post(
    'sales/order/addComment',
    { 'history[status]': 'pending', 'history[comment]': 'k6 comment' },
    'Admin Order Add Comment',
    { params: `order_id/${orderId}/`, query: 'isAjax=true', ajax: true, expect: ['Not Notified'] }
  );
  think();
  invoice(admin, orderId, 'Invoiced');
  think();
  ship(admin, orderId, 'Shipped');
}

function returns(admin) {
  const orderId = openK6Order(admin);
  if (!orderId) return skip('no pending k6 orders');
  think();
  // invoice save redirects to the order view, which carries the credit memo key
  invoice(admin, orderId, 'Invoiced');
  const start = admin.get('sales/order_creditmemo/start', 'Admin Credit Memo Start', {
    params: `order_id/${orderId}/`,
    expect: ['New Memo'],
  });
  const body = {
    'creditmemo[do_offline]': '1',
    'creditmemo[comment_text]': 'Credit Memo added',
    'creditmemo[adjustment_positive]': '0',
    'creditmemo[adjustment_negative]': '0',
  };
  for (const id of orderItemIds(start.body)) body[`creditmemo[items][${id}][qty]`] = '1';
  think();
  admin.post('sales/order_creditmemo/save', body, 'Admin Credit Memo Submit', {
    params: `order_id/${orderId}/`,
    expect: ['You created the credit memo'],
  });
}

function categoryManagement(admin, data) {
  const parentId = 2;
  admin.get('catalog/category/index', 'Admin Category Landing Page');
  admin.get('catalog/category/edit', 'Admin Select Parent Category', { params: `id/${parentId}/` });
  admin.get('catalog/category/add', 'Admin Open New Category Page', {
    params: `store/0/parent/${parentId}/`,
    expect: ['New Category'],
  });
  think();
  const name = uniq(`${PREFIX}-category-`);
  const products = {};
  for (let i = 0; i < 3; i++) products[pick(data.simples).id] = '';
  const saved = admin.post(
    'catalog/category/save',
    {
      id: '',
      parent: String(parentId),
      path: '',
      store_id: '',
      is_active: '0',
      include_in_menu: '0',
      is_anchor: '1',
      'use_config[available_sort_by]': 'true',
      'use_config[default_sort_by]': 'true',
      'use_config[filter_price_range]': 'true',
      'use_default[url_key]': 'false',
      url_key_create_redirect: '0',
      custom_use_parent_settings: '0',
      custom_apply_to_products: '0',
      name,
      url_key: name,
      display_mode: 'PRODUCTS',
      default_sort_by: 'position',
      category_products: JSON.stringify(products),
    },
    'Admin Create Category'
  );
  const categoryId =
    match(saved.url, /catalog\/category\/edit\/id\/(\d+)/) ||
    match((saved.body || '').replace(/\\\//g, '/'), /catalog\/category\/edit\/id\/(\d+)\//);
  if (!categoryId || categoryId === String(parentId)) return;
  admin.get('catalog/category/edit', 'Admin Select Created Category', { params: `id/${categoryId}/`, expect: [name] });
  think();
  const newParent = pick(data.categories).id;
  admin.post(
    'catalog/category/move',
    { id: categoryId, point: 'append', pid: String(newParent), paid: String(parentId), aid: '0' },
    'Admin Move Category',
    { ajax: true }
  );
  admin.post('catalog/category/delete', {}, 'Admin Delete Category', {
    params: `id/${categoryId}/`,
    expect: ['You deleted the category.'],
  });
}

function promo(admin) {
  admin.get('sales_rule/promo_quote/index', 'Admin Promo Landing Page');
  think();
  admin.get('sales_rule/promo_quote/new', 'Admin Promo Create New');
  admin.post(
    'sales_rule/promo_quote/newConditionHtml',
    { id: '1--1', type: 'Magento\\SalesRule\\Model\\Rule\\Condition\\Address|base_subtotal' },
    'Admin Promo New Condition',
    { params: 'form/sales_rule_formrule_conditions_fieldset_/form_namespace/sales_rule_form/', ajax: true }
  );
  think();
  const name = uniq(`${PREFIX}-rule-`);
  admin.post(
    'sales_rule/promo_quote/save',
    {
      name,
      description: name,
      is_active: '0',
      use_auto_generation: '0',
      is_rss: '0',
      apply_to_shipping: '0',
      stop_rules_processing: '0',
      coupon_code: '',
      discount_amount: '5',
      discount_qty: '0',
      coupon_type: '1',
      simple_action: 'cart_fixed',
      'website_ids[0]': '1',
      'customer_group_ids[0]': '0',
      'rule[conditions][1][type]': 'Magento\\SalesRule\\Model\\Rule\\Condition\\Combine',
      'rule[conditions][1][aggregator]': 'all',
      'rule[conditions][1][value]': '1',
      'rule[conditions][1--1][type]': 'Magento\\SalesRule\\Model\\Rule\\Condition\\Address',
      'rule[conditions][1--1][attribute]': 'base_subtotal',
      'rule[conditions][1--1][operator]': '>=',
      'rule[conditions][1--1][value]': '100',
      'rule[actions][1][type]': 'Magento\\SalesRule\\Model\\Rule\\Condition\\Product\\Combine',
      'rule[actions][1][aggregator]': 'all',
      'rule[actions][1][value]': '1',
    },
    'Admin Promo Save',
    { expect: ['You saved the rule.'] }
  );
}

function customerManagement(admin, data) {
  admin.get('customer/index/index', 'Admin Customer Landing Page');
  // harvests the customer/index/edit key from the grid row actions
  admin.grid('customer_listing', {}, 'Admin customer grid');
  admin.grid('customer_listing', { search: 'K6' }, 'Admin customer grid search');
  const customer = pick(data.customers);
  admin.get('customer/index/edit', 'Admin Edit Customer', { params: `id/${customer.id}/`, expect: ['Customer Information'] });
  think();
  const n = match(customer.email, /-user-(\d+)@/) || '0';
  const body = {
    'customer[entity_id]': String(customer.id),
    'customer[website_id]': '1',
    'customer[email]': customer.email,
    'customer[group_id]': '1',
    'customer[firstname]': 'K6',
    'customer[lastname]': `User${n}`,
    'customer[sendemail_store_id]': '1',
  };
  admin.post('customer/index/validate', body, 'Admin Customer Validate', { ajax: true, expect: [/"error":(false|0)/] });
  admin.post('customer/index/save', body, 'Admin Customer Save', { expect: ['You saved the customer.'] });
}

export const ADMIN_FLOWS = {
  cms: (a) => cms(a),
  product_grid: (a) => browseGrid(a, 'product_grid'),
  order_grid: (a) => browseGrid(a, 'order_grid'),
  customer_grid: (a) => browseGrid(a, 'customer_grid'),
  create_product: (a) => createProduct(a),
  edit_product: (a, d) => editProduct(a, d),
  returns: (a) => returns(a),
  create_order: (a, d) => createOrder(a, d),
  category: (a, d) => categoryManagement(a, d),
  promo: (a) => promo(a),
  customer_mgmt: (a, d) => customerManagement(a, d),
  edit_order: (a) => editOrder(a),
};

export function adminFlow(data, which) {
  if (!data.admin) return skip('no admin access (ADMIN_USER/ADMIN_PASSWORD unset?)');
  const key = which || weighted(mix.admin);
  session(data, key, (admin) => ADMIN_FLOWS[key](admin, data));
}
