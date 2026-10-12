// Magento benchmark (k6 port of the Performance Toolkit benchmark.jmx).
//
// PROFILE selects what runs:
//   combined   storefront mix (Luma pages) + admin mix          (default)
//   graphql    storefront mix via GraphQL + admin mix
//   storefront storefront mix only
//   admin      admin mix only
//   crawler    random-walk crawler (the original magento.js)
//   smoke      every flow once with 1 VU: functional check
//   cleanup    cancel/remove k6-created data
// See README.md for all variables.
import http from 'k6/http';
import { cfg, mix, hasAdmin } from './lib/config.js';
import { weighted } from './lib/http.js';
import { discover } from './lib/data.js';
import { bootstrap } from './lib/bootstrap.js';
import * as web from './scenarios/storefront.js';
import { guestCheckout, customerCheckout } from './scenarios/checkout.js';
import * as gq from './scenarios/graphql.js';
import { adminFlow, ADMIN_FLOWS } from './scenarios/admin.js';
import { crawl } from './scenarios/crawler.js';
import { cleanup } from './scenarios/cleanup.js';

const WEB_FLOWS = {
  browse: web.browse,
  search: web.search,
  add_to_cart: web.addToCart,
  guest_checkout: guestCheckout,
  customer_checkout: customerCheckout,
  wishlist: web.wishlist,
  compare: web.compare,
  account: web.account,
};

const GRAPHQL_FLOWS = {
  browse: gq.gqlBrowse,
  search: gq.gqlSearch,
  add_to_cart: gq.gqlAddToCart,
  guest_checkout: gq.gqlGuestCheckout,
  customer_checkout: gq.gqlCustomerCheckout,
  wishlist: gq.gqlWishlist,
  compare: gq.gqlCompare,
  account: gq.gqlAccount,
};

const CUSTOMER_FLOWS = ['customer_checkout', 'wishlist', 'account'];

const loadStages = [
  { duration: cfg.rampUp, target: cfg.vus },
  { duration: cfg.duration, target: cfg.vus },
  { duration: cfg.rampDown, target: 0 },
];

function storefrontScenario(exec) {
  return { executor: 'ramping-vus', exec, startVUs: 0, stages: loadStages, gracefulRampDown: '30s' };
}

function adminScenario() {
  return {
    executor: 'ramping-vus',
    exec: 'adminMix',
    startVUs: 0,
    stages: [
      { duration: cfg.rampUp, target: cfg.adminVus },
      { duration: cfg.duration, target: cfg.adminVus },
      { duration: cfg.rampDown, target: 0 },
    ],
    gracefulRampDown: '60s',
  };
}

function once(exec) {
  return { executor: 'per-vu-iterations', exec, vus: 1, iterations: 1, maxDuration: '30m' };
}

function scenarios() {
  const withAdmin = hasAdmin() && cfg.adminVus > 0;
  switch (cfg.profile) {
    case 'graphql':
      return Object.assign({ storefront: storefrontScenario('graphqlMix') }, withAdmin ? { admin: adminScenario() } : {});
    case 'storefront':
      return { storefront: storefrontScenario('storefrontMix') };
    case 'admin':
      return { admin: adminScenario() };
    case 'crawler':
      return { crawler: storefrontScenario('crawler') };
    case 'smoke':
      return { smoke: once('smoke') };
    case 'cleanup':
      return { cleanup: once('cleanupRun') };
    default:
      return Object.assign({ storefront: storefrontScenario('storefrontMix') }, withAdmin ? { admin: adminScenario() } : {});
  }
}

const quiet = ['cleanup'].includes(cfg.profile);

export const options = {
  scenarios: scenarios(),
  insecureSkipTLSVerify: true,
  summaryTrendStats: ['min', 'med', 'avg', 'p(90)', 'p(95)', 'max'],
  rps: cfg.rps || undefined,
  setupTimeout: '10m',
  thresholds: quiet
    ? {}
    : {
        http_req_failed: ['rate<0.05'],
        magento_errors: ['rate<0.05'],
        magento_page_duration: ['p(95)<5000'],
      },
};

function needsBootstrap() {
  return ['combined', 'graphql', 'storefront', 'admin', 'smoke'].includes(cfg.profile);
}

export function setup() {
  if (!needsBootstrap()) return {};
  const catalog = discover();
  console.log(
    `Catalog: ${catalog.categories.length} categories, ${catalog.simples.length} simple, ${catalog.configurables.length} configurable products`
  );
  let boot = { customers: [], customerPassword: null, adminUsers: [], k6Products: [] };
  if (hasAdmin()) {
    const wantAdminUsers = cfg.profile !== 'storefront' && cfg.adminVus > 0;
    boot = bootstrap(catalog.regionId, wantAdminUsers);
  } else {
    console.warn('ADMIN_USER/ADMIN_PASSWORD not set: customer and admin flows are disabled');
  }
  return Object.assign(catalog, boot);
}

function storefrontWeights(data) {
  const weights = Object.assign({}, mix.storefront);
  if (!data.customers || data.customers.length === 0) {
    for (const k of CUSTOMER_FLOWS) weights[k] = 0;
  }
  return weights;
}

export function storefrontMix(data) {
  WEB_FLOWS[weighted(storefrontWeights(data))](data);
}

export function graphqlMix(data) {
  GRAPHQL_FLOWS[weighted(storefrontWeights(data))](data);
}

export function adminMix(data) {
  adminFlow(data);
}

export function crawler(data) {
  crawl(data);
}

export function cleanupRun() {
  cleanup();
}

// Every flow once, in an order where later flows find what earlier ones made
// (orders for the admin order flows, etc.). Cookies are cleared between flows
// so each starts with a fresh session, as it would in its own iteration.
export function smoke(data) {
  const hasCustomers = data.customers && data.customers.length > 0;
  const run = (group) => cfg.smokeGroups.includes(group);
  for (const key of run('web') ? Object.keys(WEB_FLOWS) : []) {
    if (CUSTOMER_FLOWS.includes(key) && !hasCustomers) continue;
    http.cookieJar().clear(cfg.baseUrl);
    if (key === 'search') ['quick', 'quick_filter', 'advanced'].forEach((k) => web.search(data, k));
    else WEB_FLOWS[key](data);
  }
  for (const key of run('graphql') ? Object.keys(GRAPHQL_FLOWS) : []) {
    if (CUSTOMER_FLOWS.includes(key) && !hasCustomers) continue;
    if (key === 'search') ['quick', 'quick_filter'].forEach((k) => gq.gqlSearch(data, k));
    else GRAPHQL_FLOWS[key](data);
  }
  if (run('admin') && data.adminUsers && data.adminUsers.length) {
    for (const key of Object.keys(ADMIN_FLOWS)) {
      http.cookieJar().clear(cfg.baseUrl);
      adminFlow(data, key);
    }
  }
}

// Used when the script is run with plain --vus/--duration flags.
export default function (data) {
  if (cfg.profile === 'crawler') crawl(data);
  else if (cfg.profile === 'graphql') graphqlMix(data);
  else storefrontMix(data);
}
