// Luma storefront flows ported from the JMX "Combined Benchmark Pool":
// catalog browsing, site search (quick / quick + layered nav / advanced),
// guest add to cart, compare products, wishlist.
import http from 'k6/http';
import exec from 'k6/execution';
import { group } from 'k6';
import { cfg, mix } from '../lib/config.js';
import { get, post, think, pick, pickDistinct, weighted, match, initFormKey, AJAX } from '../lib/http.js';
import { derivedPassword } from '../lib/bootstrap.js';

const IN_STOCK = '<span>In stock</span>';

// Scenarios run separately (not combined), so VU IDs always start from 1 and
// reach at most vus — well within the customerCount pool (vus*3). Plain modulo
// gives each VU a unique customer with no cross-scenario collision possible.
export function customerFor(data) {
  const n = data.customers.length;
  return data.customers[(exec.vu.idInTest - 1) % n];
}

export function home() {
  return get('', 'Home Page', { expect: ['<title>Home Page</title>'] });
}

export function category(data) {
  const c = pick(data.categories);
  const title = c.name.replace(/&/g, '&amp;').replace(/'/g, '&#039;');
  get(c.url, 'Category Page', { expect: [`<title>${title}`] });
  return c;
}

export function productView(product, kind) {
  return get(product.url, `${kind} Product View`, { expect: [IN_STOCK] });
}

export function loadSections(sections, name, expect) {
  const q = `sections=${encodeURIComponent(sections)}&force_new_section_timestamp=true&_=${Date.now()}`;
  return get(`customer/section/load/?${q}`, name, { noBust: true, headers: AJAX, expect });
}

function cartCountAtLeast(n) {
  return Object.assign(
    (r) => {
      const m = (r.body || '').match(/"summary_count":(\d+)/);
      return m !== null && parseInt(m[1], 10) >= n;
    },
    { label: `cart has >= ${n} items` }
  );
}

// Adds `simple` simple and `configurable` configurable products to the cart,
// viewing each product first, the way the JMX loops do. Returns items added.
export function addProductsToCart(data, fk, simple, configurable) {
  let added = 0;
  for (let i = 0; i < simple; i++) {
    const p = pick(data.simples);
    productView(p, 'Simple');
    post('checkout/cart/add/', { product: p.id, related_product: '', qty: 1, form_key: fk }, 'Simple Product Add To Cart', {
      headers: AJAX,
    });
    added++;
    const sr = loadSections('cart,messages', 'Load Cart Section', [cartCountAtLeast(added)]);
    const sm = (sr.body || '').match(/"summary_count":(\d+)/);
    if (sm) added = parseInt(sm[1], 10);
    think();
  }
  for (let i = 0; i < configurable; i++) {
    const p = pick(data.configurables);
    productView(p, 'Configurable');
    const body = { product: p.id, related_product: '', qty: 1, form_key: fk };
    for (const attrId of Object.keys(p.superAttributes)) body[`super_attribute[${attrId}]`] = p.superAttributes[attrId];
    post('checkout/cart/add/', body, 'Configurable Product Add To Cart', { headers: AJAX });
    added++;
    const cr = loadSections('cart,messages', 'Load Cart Section', [cartCountAtLeast(added)]);
    const cm = (cr.body || '').match(/"summary_count":(\d+)/);
    if (cm) added = parseInt(cm[1], 10);
    think();
  }
  return added;
}

export function customerLogin(data) {
  const customer = customerFor(data);
  const fk = initFormKey();
  get('customer/account/login/', 'Customer Login Page', { expect: ['<title>Customer Login</title>'] });
  const res = post(
    'customer/account/loginPost/',
    { form_key: fk, 'login[username]': customer.email, 'login[password]': derivedPassword(), send: '' },
    'Customer Login',
    { expect: ['<title>My Account</title>'] }
  );
  const addressId = match(res.body, /customer\/address\/edit\/id\/(\d+)\//);
  // login regenerates the session and deletes the form_key cookie: plant a new one
  const sessionKey = initFormKey();
  loadSections('', 'Load Customer Private Data');
  return { customer, fk: sessionKey, addressId, ok: (res.body || '').includes('<title>My Account</title>') };
}

export function customerLogout() {
  get('customer/account/logout/', 'Customer Logout', { noBust: true });
}

export function browse(data) {
  group('Catalog Browsing By Guest', () => {
    initFormKey();
    home();
    think();
    category(data);
    think();
    for (let i = 0; i < 2; i++) {
      productView(pick(data.simples), 'Simple');
      think();
    }
    for (let i = 0; i < 2; i++) {
      productView(pick(data.configurables), 'Configurable');
      think();
    }
  });
}

function resultProductLinks(body) {
  const links = [];
  const re = /<a\s+class="product-item-link"\s+href="([^"]+)"/g;
  let m;
  while ((m = re.exec(body || '')) !== null) links.push(m[1]);
  return links;
}

function filterLinks(body) {
  // first link inside each layered-navigation filter block
  return (body || '')
    .split('class="filter-options-content"')
    .slice(1)
    .map((block) => match(block, /<a\s+href="([^"]+)"/))
    .filter(Boolean)
    .map((h) => h.replace(/&amp;/g, '&'));
}

function viewSearchResults(links) {
  for (const link of links.slice(0, 2)) {
    get(link, 'Searched Product View', { expect: [IN_STOCK] });
    think();
  }
}

function quickSearch(withFilter) {
  const term = pick(cfg.searchTerms).trim();
  home();
  think();
  let res = get(`catalogsearch/result/?q=${encodeURIComponent(term)}`, 'Quick Search', {
    expect: ['Search results for'],
  });
  if ((res.body || '').includes('catalogsearch/searchTermsLog/save')) {
    get(`catalogsearch/searchTermsLog/save/?q=${encodeURIComponent(term)}`, 'Search Terms Log', {
      noBust: true,
      headers: AJAX,
      expect: ['"success":true'],
    });
  }
  think();
  if (withFilter) {
    const filters = filterLinks(res.body);
    if (filters[0]) {
      res = get(filters[0], 'Filter by Attribute 1', { expect: ['Search results for'] });
      think();
      const next = filterLinks(res.body)[1];
      if (next) {
        res = get(next, 'Filter by Attribute 2', { expect: ['Search results for'] });
        think();
      }
    }
  }
  viewSearchResults(resultProductLinks(res.body));
}

function advancedSearch() {
  const term = pick(cfg.searchTerms).trim();
  home();
  think();
  get('catalogsearch/advanced/', 'Open Advanced Search', { expect: ['<title>Advanced Search</title>'] });
  think();
  const res = get(
    `catalogsearch/advanced/result/?name=&sku=&description=${encodeURIComponent(term)}&short_description=&price%5Bfrom%5D=&price%5Bto%5D=500`,
    'Advanced Search',
    { expect: [/were found using the following search criteria|can't find any items|Advanced Search/i] }
  );
  think();
  viewSearchResults(resultProductLinks(res.body));
}

export function search(data, which) {
  const kind = which || weighted(mix.search);
  group('Site Search', () => {
    initFormKey();
    if (kind === 'quick') quickSearch(false);
    else if (kind === 'quick_filter') quickSearch(true);
    else advancedSearch();
  });
}

export function addToCart(data) {
  group('Add To Cart By Guest', () => {
    http.cookieJar().clear(cfg.baseUrl);
    const fk = initFormKey();
    home();
    think();
    category(data);
    think();
    addProductsToCart(data, fk, 2, 2);
  });
}

export function compare(data) {
  group('Compare Products', () => {
    const fk = initFormKey();
    category(data);
    think();
    // distinct products, otherwise a repeat add leaves the compare count unchanged
    const [first, second] = pickDistinct(data.simples, 2);
    const products = [
      [first, 'Simple'],
      [second, 'Simple'],
      [pick(data.configurables), 'Configurable'],
    ];
    products.forEach(([p, kind], i) => {
      const page = productView(p, kind);
      const uenc = match(page.body, /\/uenc\/([^/]+)\/product\//) || '';
      post('catalog/product_compare/add/', { product: p.id, form_key: fk, uenc }, 'Compare Add', { headers: AJAX });
      loadSections('compare-products,messages', 'Load Compare Section', [
        Object.assign((r) => (r.body || '').includes(`"compare-products":{"count":${i + 1}`), {
          label: 'compare count matches',
        }),
      ]);
      think();
    });
    get('catalog/product_compare/index/', 'Compare Products Page', { noBust: true });
    think();
    post('catalog/product_compare/clear', { form_key: fk }, 'Compare Clear');
  });
}

export function wishlist(data) {
  group('Add to Wishlist', () => {
    const session = customerLogin(data);
    if (!session.ok) return;
    think();
    let page = null;
    for (let i = 0; i < 2; i++) {
      const p = pick(data.simples);
      const view = productView(p, 'Simple');
      const uenc = match(view.body, /\/uenc\/([^/]+)\/product\//) || '';
      page = post('wishlist/index/add/', { form_key: session.fk, uenc, product: p.id }, 'Add To Wishlist', {
        expect: ['<title>My Wish List</title>'],
      });
      loadSections('wishlist,messages', 'Load Wishlist Section', ['"wishlist":{']);
      think();
    }
    const body = ((page && page.body) || '').replace(/\\\//g, '/');
    const items = [];
    const re = /wishlist\/index\/remove\/","data":\{"item":"?(\d+)/g;
    let m;
    while ((m = re.exec(body)) !== null) items.push(m[1]);
    for (const item of new Set(items)) {
      post('wishlist/index/remove/', { form_key: session.fk, item }, 'Clear Wishlist Item');
    }
    customerLogout();
  });
}

export function account(data) {
  group('Account Management', () => {
    home();
    think();
    const session = customerLogin(data);
    if (!session.ok) return;
    think();
    const orders = get('sales/order/history/', 'My Orders', { noBust: true, expect: ['<title>My Orders</title>'] });
    const orderId = match(orders.body, /sales\/order\/view\/order_id\/(\d+)\//);
    if (orderId) {
      think();
      get(`sales/order/view/order_id/${orderId}/`, 'View Order', { noBust: true, expect: ['<title>Order #'] });
    }
    think();
    get('downloadable/customer/products/', 'My Downloadable Products', {
      noBust: true,
      expect: ['<title>My Downloadable Products</title>'],
    });
    think();
    const wl = get('wishlist/', 'My Wish List', { noBust: true, expect: ['<title>My Wish List</title>'] });
    const wishlistId = match(wl.body, /wishlist\/index\/update\/wishlist_id\/(\d+)\//);
    if (wishlistId) {
      think();
      get(`wishlist/index/share/wishlist_id/${wishlistId}/`, 'Share Wish List', {
        noBust: true,
        expect: ['<title>Wish List Sharing</title>'],
      });
    }
    customerLogout();
  });
}
