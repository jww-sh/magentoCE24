// GraphQL versions of the storefront flows (JMX "GraphQL Combined Benchmark Pool"),
// i.e. what a PWA/headless frontend sends.
import exec from 'k6/execution';
import encoding from 'k6/encoding';
import { group } from 'k6';
import { cfg, mix, taggedEmail } from '../lib/config.js';
import { verify, think, pick, weighted, ordersPlaced } from '../lib/http.js';
import { gql } from '../lib/data.js';
import { derivedPassword } from '../lib/bootstrap.js';
import { customerFor } from './storefront.js';

function q(name, query, variables, token, expectPath) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const r = gql(query, variables, headers, name);
  const expect = [Object.assign(() => !r.errors, { label: 'no GraphQL errors' })];
  if (expectPath) expect.push(Object.assign(() => Boolean(dig(r.data, expectPath)), { label: `has ${expectPath}` }));
  verify(r.res, name, expect);
  if (r.errors && cfg.debug) console.warn(`[VU ${exec.vu.idInTest}] ${name}: ${JSON.stringify(r.errors)}`);
  return r.data;
}

function dig(obj, path) {
  return path.split('.').reduce((o, k) => (o == null ? o : o[k]), obj);
}

const PRODUCT_FIELDS = `__typename id sku name url_key stock_status
  price_range{ minimum_price{ final_price{ value currency } } }
  small_image{ url label } description{ html }`;

function navigationMenu() {
  return q(
    'GraphQL Navigation Menu',
    `{ categoryList(filters:{}){ id name children{ id name url_path include_in_menu children{ id name url_path } } } }`,
    {},
    null,
    'categoryList'
  );
}

function categoryProducts(categoryId) {
  return q(
    'GraphQL List Products by category_id',
    `query($id:String!){ products(filter:{category_id:{eq:$id}}, pageSize:12, currentPage:1){
       total_count items{ ${PRODUCT_FIELDS} } aggregations{ attribute_code count options{ label value } } } }`,
    { id: String(categoryId) },
    null,
    'products'
  );
}

function productDetail(urlKey, kind) {
  return q(
    `GraphQL ${kind} Product Details by url_key`,
    `query($k:String!){ products(filter:{url_key:{eq:$k}}){ items{ ${PRODUCT_FIELDS}
       ... on ConfigurableProduct{ configurable_options{ attribute_code values{ value_index label } }
         variants{ product{ sku stock_status } attributes{ code value_index } } } } } }`,
    { k: urlKey },
    null,
    'products.items.0'
  );
}

function urlKey(product) {
  return product.url.replace(/\.html$/, '');
}

function createCart(token) {
  if (token) {
    const d = q('GraphQL Customer Cart', `{ customerCart{ id total_quantity } }`, {}, token, 'customerCart.id');
    return d && d.customerCart.id;
  }
  const d = q('GraphQL Create Empty Cart', `mutation{ createEmptyCart }`, {}, null, 'createEmptyCart');
  return d && d.createEmptyCart;
}

function addToCart(cartId, data, token, simple, configurable) {
  for (let i = 0; i < simple; i++) {
    const p = pick(data.simples);
    productDetail(urlKey(p), 'Simple');
    q(
      'GraphQL Add Simple Product To Cart',
      `mutation($cart:String!,$sku:String!){ addProductsToCart(cartId:$cart, cartItems:[{sku:$sku, quantity:1}]){
         cart{ total_quantity } user_errors{ code message } } }`,
      { cart: cartId, sku: p.sku },
      token,
      'addProductsToCart.cart'
    );
    think();
  }
  for (let i = 0; i < configurable; i++) {
    const p = pick(data.configurables);
    productDetail(urlKey(p), 'Configurable');
    // configurable children are addressed by parent_sku + selected option uids
    const selected = Object.keys(p.superAttributes).map((id) =>
      encoding.b64encode(`configurable/${id}/${p.superAttributes[id]}`)
    );
    q(
      'GraphQL Add Configurable Product To Cart',
      `mutation($cart:String!,$sku:String!,$opts:[ID!]){ addProductsToCart(cartId:$cart,
         cartItems:[{sku:$sku, quantity:1, selected_options:$opts}]){ cart{ total_quantity } user_errors{ code message } } }`,
      { cart: cartId, sku: p.sku, opts: selected },
      token,
      'addProductsToCart.cart'
    );
    think();
  }
}

function gqlAddress(data, firstname, lastname) {
  const a = cfg.address;
  const out = {
    firstname,
    lastname,
    street: [a.street],
    city: a.city,
    postcode: a.postcode,
    country_code: a.countryId,
    telephone: a.telephone,
    save_in_address_book: false,
  };
  if (data.regionId) out.region_id = data.regionId;
  else out.region = a.region;
  return out;
}

// Removes all items currently in the cart before adding fresh ones.
// Prevents leftover items from a failed previous iteration from stacking up.
function clearGQLCart(cartId, token) {
  const d = q('GraphQL Get Cart Items', `query($c:String!){ cart(cart_id:$c){ items{ uid } } }`, { c: cartId }, token, null);
  for (const item of (d && d.cart && d.cart.items) || []) {
    q(
      'GraphQL Remove Cart Item',
      `mutation($c:String!,$u:ID!){ removeItemFromCart(input:{cart_id:$c,cart_item_uid:$u}){ cart{ total_quantity } } }`,
      { c: cartId, u: item.uid },
      token,
      null
    );
  }
}

function checkoutCart(cartId, data, token, email) {
  const addr = gqlAddress(data, 'K6', token ? 'Customer' : 'Guest');
  if (!token) {
    q(
      'GraphQL Set Guest Email',
      `mutation($cart:String!,$email:String!){ setGuestEmailOnCart(input:{cart_id:$cart, email:$email}){ cart{ email } } }`,
      { cart: cartId, email },
      null,
      'setGuestEmailOnCart.cart'
    );
  }
  const shippingResult = q(
    'GraphQL Set Shipping Address On Cart',
    `mutation($cart:String!,$addr:CartAddressInput!){ setShippingAddressesOnCart(input:{cart_id:$cart,
       shipping_addresses:[{address:$addr}]}){ cart{ shipping_addresses{ available_shipping_methods{ carrier_code method_code } } } } }`,
    { cart: cartId, addr },
    token,
    'setShippingAddressesOnCart.cart'
  );
  if (!dig(shippingResult, 'setShippingAddressesOnCart.cart')) return;
  q(
    'GraphQL Set Billing Address On Cart',
    `mutation($cart:String!,$addr:CartAddressInput!){ setBillingAddressOnCart(input:{cart_id:$cart,
       billing_address:{address:$addr}}){ cart{ billing_address{ city } } } }`,
    { cart: cartId, addr },
    token,
    'setBillingAddressOnCart.cart'
  );
  q(
    'GraphQL Set Shipping Method On Cart',
    `mutation($cart:String!,$c:String!,$m:String!){ setShippingMethodsOnCart(input:{cart_id:$cart,
       shipping_methods:[{carrier_code:$c, method_code:$m}]}){ cart{ prices{ grand_total{ value } } } } }`,
    { cart: cartId, c: cfg.shippingCarrier, m: cfg.shippingMethod },
    token,
    'setShippingMethodsOnCart.cart'
  );
  q(
    'GraphQL Set Payment Method On Cart',
    `mutation($cart:String!,$p:String!){ setPaymentMethodOnCart(input:{cart_id:$cart, payment_method:{code:$p}}){
       cart{ selected_payment_method{ code } } } }`,
    { cart: cartId, p: cfg.paymentMethod },
    token,
    'setPaymentMethodOnCart.cart'
  );
  think();
  const placed = q(
    'GraphQL Place Order',
    `mutation($cart:String!){ placeOrder(input:{cart_id:$cart}){ orderV2{ number } errors{ code message } } }`,
    { cart: cartId },
    token,
    'placeOrder.orderV2.number'
  );
  if (dig(placed, 'placeOrder.orderV2.number')) ordersPlaced.add(1, { flow: token ? 'graphql_customer' : 'graphql_guest' });
}

// Tokens are left to expire rather than revoked: revokeCustomerToken invalidates
// every token of that customer issued up to the same second, which breaks the
// next flow that logs in as the same customer.
export function customerToken(data) {
  const customer = customerFor(data);
  const d = q(
    'GraphQL Generate Customer Token',
    `mutation($e:String!,$p:String!){ generateCustomerToken(email:$e, password:$p){ token } }`,
    { e: customer.email, p: derivedPassword() },
    null,
    'generateCustomerToken.token'
  );
  return d && d.generateCustomerToken.token;
}

export function gqlBrowse(data) {
  group('GraphQL Catalog Browsing By Guest', () => {
    navigationMenu();
    think();
    categoryProducts(pick(data.categories).id);
    think();
    for (let i = 0; i < 2; i++) {
      productDetail(urlKey(pick(data.simples)), 'Simple');
      think();
    }
    for (let i = 0; i < 2; i++) {
      productDetail(urlKey(pick(data.configurables)), 'Configurable');
      think();
    }
  });
}

export function gqlSearch(data, which) {
  const kind = which || weighted(mix.search);
  group('GraphQL Site Search', () => {
    const term = pick(cfg.searchTerms).trim();
    navigationMenu();
    think();
    const first = q(
      'GraphQL Product Search',
      `query($s:String!){ products(search:$s, pageSize:12){ total_count items{ ${PRODUCT_FIELDS} }
         aggregations{ attribute_code options{ value } } } }`,
      { s: term },
      null,
      'products'
    );
    let items = (first && first.products.items) || [];
    if (kind !== 'quick' && first) {
      // filter by the first category aggregation, like layered navigation / advanced search
      const agg = (first.products.aggregations || []).find((a) => a.attribute_code === 'category_uid' && a.options.length);
      if (agg) {
        think();
        const filtered = q(
          'GraphQL Product Search With Filter',
          `query($s:String!,$c:String!){ products(search:$s, filter:{category_uid:{eq:$c}}, pageSize:12){
             total_count items{ ${PRODUCT_FIELDS} } } }`,
          { s: term, c: agg.options[0].value },
          null,
          'products'
        );
        if (filtered) items = filtered.products.items;
      }
    }
    for (const p of items.slice(0, 2)) {
      think();
      productDetail(p.url_key, p.__typename === 'ConfigurableProduct' ? 'Configurable' : 'Simple');
    }
  });
}

export function gqlAddToCart(data) {
  group('GraphQL Add To Cart By Guest', () => {
    navigationMenu();
    think();
    categoryProducts(pick(data.categories).id);
    think();
    const cartId = createCart(null);
    if (!cartId) return;
    addToCart(cartId, data, null, 2, 2);
    q('GraphQL Get Cart', `query($c:String!){ cart(cart_id:$c){ total_quantity items{ uid quantity } } }`, { c: cartId }, null, 'cart');
  });
}

export function gqlGuestCheckout(data) {
  group('GraphQL Checkout By Guest', () => {
    categoryProducts(pick(data.categories).id);
    think();
    const cartId = createCart(null);
    if (!cartId) return;
    addToCart(cartId, data, null, 2, 2);
    const email = taggedEmail('guest', exec.vu.idInTest, exec.vu.iterationInScenario, Date.now());
    checkoutCart(cartId, data, null, email);
  });
}

export function gqlCustomerCheckout(data) {
  group('GraphQL Checkout By Customer', () => {
    const token = customerToken(data);
    if (!token) return;
    think();
    categoryProducts(pick(data.categories).id);
    think();
    const cartId = createCart(token);
    if (!cartId) return;
    clearGQLCart(cartId, token);
    addToCart(cartId, data, token, 2, 2);
    checkoutCart(cartId, data, token, null);
  });
}

export function gqlWishlist(data) {
  group('GraphQL Add to Wishlist', () => {
    const token = customerToken(data);
    if (!token) return;
    const wl = q('GraphQL Get Wishlist', `{ customer{ wishlists{ id items_count } } }`, {}, token, 'customer.wishlists');
    const wishlistId = dig(wl, 'customer.wishlists.0.id');
    if (!wishlistId) return;
    for (let i = 0; i < 2; i++) {
      const p = pick(data.simples);
      productDetail(urlKey(p), 'Simple');
      q(
        'GraphQL Add Product To Wishlist',
        `mutation($w:ID!,$sku:String!){ addProductsToWishlist(wishlistId:$w, wishlistItems:[{sku:$sku, quantity:1}]){
           wishlist{ items_count } user_errors{ message } } }`,
        { w: wishlistId, sku: p.sku },
        token,
        'addProductsToWishlist.wishlist'
      );
      think();
    }
    const items = q(
      'GraphQL Wishlist Items',
      `{ customer{ wishlists{ id items_v2{ items{ id } } } } }`,
      {},
      token,
      'customer.wishlists'
    );
    const ids = (dig(items, 'customer.wishlists.0.items_v2.items') || []).map((x) => x.id);
    if (ids.length) {
      q(
        'GraphQL Remove Products From Wishlist',
        `mutation($w:ID!,$ids:[ID!]!){ removeProductsFromWishlist(wishlistId:$w, wishlistItemsIds:$ids){ wishlist{ items_count } } }`,
        { w: wishlistId, ids },
        token,
        'removeProductsFromWishlist.wishlist'
      );
    }
  });
}

export function gqlCompare(data) {
  group('GraphQL Compare Products', () => {
    categoryProducts(pick(data.categories).id);
    think();
    const products = [pick(data.simples), pick(data.simples), pick(data.configurables)];
    const created = q('GraphQL Create Compare List', `mutation{ createCompareList{ uid } }`, {}, null, 'createCompareList.uid');
    const uid = dig(created, 'createCompareList.uid');
    if (!uid) return;
    for (const p of products) {
      think();
      q(
        'GraphQL Add Products To Compare List',
        `mutation($u:ID!,$p:[ID]!){ addProductsToCompareList(input:{uid:$u, products:$p}){ item_count } }`,
        { u: uid, p: [String(p.id)] },
        null,
        'addProductsToCompareList'
      );
    }
    q(
      'GraphQL Compare List',
      `query($u:ID!){ compareList(uid:$u){ item_count attributes{ code label } items{ product{ sku name } } } }`,
      { u: uid },
      null,
      'compareList'
    );
    q('GraphQL Delete Compare List', `mutation($u:ID!){ deleteCompareList(uid:$u){ result } }`, { u: uid }, null);
  });
}

export function gqlAccount(data) {
  group('GraphQL Account Management', () => {
    const token = customerToken(data);
    if (!token) return;
    q(
      'GraphQL Customer Info',
      `{ customer{ firstname lastname email addresses{ id city default_billing } } }`,
      {},
      token,
      'customer.email'
    );
    think();
    q(
      'GraphQL Customer Orders',
      `{ customer{ orders(pageSize:10){ total_count items{ number status total{ grand_total{ value } } } } } }`,
      {},
      token,
      'customer.orders'
    );
    think();
    q('GraphQL Customer Wishlist', `{ customer{ wishlists{ id items_count } } }`, {}, token, 'customer.wishlists');
  });
}
