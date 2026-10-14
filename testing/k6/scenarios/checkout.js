// Checkout flows from the JMX: guest checkout via guest-carts REST and customer
// checkout via carts/mine REST (session-authenticated, like the Luma checkout JS).
import http from 'k6/http';
import exec from 'k6/execution';
import { group } from 'k6';
import { cfg, taggedEmail } from '../lib/config.js';
import { get, postJson, think, match, initFormKey, ordersPlaced, url, baseHeaders } from '../lib/http.js';
import { home, category, addProductsToCart, customerLogin, customerLogout } from './storefront.js';

const REFERER = { Referer: `${cfg.baseUrl}/checkout/` };

function address(data, firstname, lastname) {
  const a = cfg.address;
  const out = {
    countryId: a.countryId,
    regionCode: a.regionCode,
    region: a.region,
    street: [a.street],
    company: '',
    telephone: a.telephone,
    postcode: a.postcode,
    city: a.city,
    firstname,
    lastname,
  };
  if (data.regionId) out.regionId = data.regionId;
  return out;
}

// Clears all items from the customer's server-side cart before adding fresh ones.
// Without this, a failed checkout leaves items behind; the next iteration adds on
// top, causing unexpected item counts and "shipping method missing" cascades.
const REST_HEADERS = { 'Content-Type': 'application/json', Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' };

function clearCustomerCart() {
  const res = get('rest/default/V1/carts/mine/items', 'Cart Clear - Get Items', { noBust: true, headers: REST_HEADERS });
  if (res.status !== 200) return;
  let items = [];
  try { items = JSON.parse(res.body || '[]'); } catch (e) {}
  if (!Array.isArray(items)) return;
  for (const item of items) {
    http.del(url(`rest/default/V1/carts/mine/items/${item.item_id}`), null, {
      headers: Object.assign(baseHeaders(), REST_HEADERS),
      tags: { name: 'Cart Clear - Delete Item' },
    });
  }
}

function orderPlaced(name) {
  return Object.assign((r) => /^"?\d+"?$/.test((r.body || '').trim()), { label: `${name} returns order id` });
}

export function guestCheckout(data) {
  group('Checkout By Guest', () => {
    http.cookieJar().clear(cfg.baseUrl);
    const fk = initFormKey();
    home();
    think();
    category(data);
    think();
    addProductsToCart(data, fk, 2, 2);

    const start = get('checkout/', 'Checkout Start', { noBust: true, expect: ['<title>Checkout</title>'] });
    const cartId = match(start.body, /"quoteData":\{"entity_id":"([^"]+)"/);
    if (!cartId) return;
    const email = taggedEmail('guest', exec.vu.idInTest, exec.vu.iterationInScenario, Date.now());
    think();

    postJson('rest/default/V1/customers/isEmailAvailable', { customerEmail: email }, 'Checkout Email Available', {
      headers: REFERER,
      expect: ['true'],
    });
    const estimateRes = postJson(
      `rest/default/V1/guest-carts/${cartId}/estimate-shipping-methods`,
      { address: { country_id: cfg.address.countryId, postcode: cfg.address.postcode } },
      'Checkout Estimate Shipping Methods',
      { headers: REFERER, expect: ['"available":true'] }
    );
    if (estimateRes.status !== 200) return;
    const addr = address(data, 'K6', 'Guest');
    const guestShipping = postJson(
      `rest/default/V1/guest-carts/${cartId}/shipping-information`,
      {
        addressInformation: {
          shipping_address: addr,
          shipping_method_code: cfg.shippingMethod,
          shipping_carrier_code: cfg.shippingCarrier,
        },
      },
      'Checkout Shipping Information',
      { headers: REFERER, expect: ['"payment_methods"'] }
    );
    if (guestShipping.status !== 200) return;
    think();
    const order = postJson(
      `rest/default/V1/guest-carts/${cartId}/payment-information`,
      {
        cartId,
        email,
        paymentMethod: { method: cfg.paymentMethod, po_number: null, additional_data: null },
        billingAddress: addr,
      },
      'Checkout Place Order',
      { headers: REFERER, expect: [orderPlaced('Place Order')] }
    );
    if (order.status !== 200) return;
    ordersPlaced.add(1, { flow: 'guest' });
    get('checkout/onepage/success/', 'Checkout Success', { noBust: true, expect: ['Thank you for your purchase!'] });
  });
}

export function customerCheckout(data) {
  group('Checkout By Customer', () => {
    http.cookieJar().clear(cfg.baseUrl);
    home();
    think();
    const session = customerLogin(data);
    if (!session.ok) return;
    clearCustomerCart();
    think();
    category(data);
    think();
    addProductsToCart(data, session.fk, 2, 2);

    const start = get('checkout/', 'Checkout Start', { noBust: true, expect: ['<title>Checkout</title>'] });
    const cartId = match(start.body, /"quoteData":\{"entity_id":"([^"]+)"/);
    const addressId = match(start.body, /"default_billing":"(\d+)"/) || session.addressId;
    const customerId = match(start.body, /"customer_id":"?(\d+)/);
    if (!cartId || !addressId) {
      customerLogout();
      return;
    }
    think();

    const estimateRes = postJson(
      'rest/default/V1/carts/mine/estimate-shipping-methods-by-address-id',
      { addressId },
      'Checkout Estimate Shipping Methods',
      { headers: REFERER, expect: ['"available":true'] }
    );
    if (estimateRes.status !== 200) {
      customerLogout();
      return;
    }
    const addr = Object.assign(address(data, 'K6', 'Customer'), { customerAddressId: addressId, customerId });
    const custShipping = postJson(
      'rest/default/V1/carts/mine/shipping-information',
      {
        addressInformation: {
          shipping_address: addr,
          shipping_method_code: cfg.shippingMethod,
          shipping_carrier_code: cfg.shippingCarrier,
        },
      },
      'Checkout Shipping Information',
      { headers: REFERER, expect: ['"payment_methods"'] }
    );
    if (custShipping.status !== 200) {
      customerLogout();
      return;
    }
    think();
    const order = postJson(
      'rest/default/V1/carts/mine/payment-information',
      {
        cartId,
        paymentMethod: { method: cfg.paymentMethod, po_number: null, additional_data: null },
        billingAddress: addr,
      },
      'Checkout Place Order',
      { headers: REFERER, expect: [orderPlaced('Place Order')] }
    );
    if (order.status !== 200) {
      customerLogout();
      return;
    }
    ordersPlaced.add(1, { flow: 'customer' });
    get('checkout/onepage/success/', 'Checkout Success', { noBust: true, expect: ['Thank you for your purchase!'] });
    customerLogout();
  });
}
