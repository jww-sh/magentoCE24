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
import { varnishChecks } from './scenarios/varnish.js';
import { runIteration } from './lib/failures.js';

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
  return { executor: 'ramping-vus', exec, startVUs: 0, stages: loadStages, gracefulRampDown: '90s', gracefulStop: '100s' };
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
    gracefulRampDown: '90s',
    gracefulStop: '100s',
  };
}

function once(exec) {
  return { executor: 'per-vu-iterations', exec, vus: 1, iterations: 1, maxDuration: '30m', gracefulStop: '100s' };
}

// Varnish cache checks run once alongside every load profile (and inside smoke)
const varnishScenario = { varnish: { executor: 'per-vu-iterations', exec: 'varnish', vus: 1, iterations: 1, maxDuration: '3m', gracefulStop: '100s' } };

function scenarios() {
  const withAdmin = hasAdmin() && cfg.adminVus > 0;
  switch (cfg.profile) {
    case 'graphql':
      return Object.assign({ storefront: storefrontScenario('graphqlMix') }, varnishScenario, withAdmin ? { admin: adminScenario() } : {});
    case 'storefront':
      return Object.assign({ storefront: storefrontScenario('storefrontMix') }, varnishScenario);
    case 'admin':
      return { admin: adminScenario() };
    case 'crawler':
      return { crawler: storefrontScenario('crawler') };
    case 'smoke':
      return { smoke: once('smoke') };
    case 'cleanup':
      return { cleanup: once('cleanupRun') };
    default:
      return Object.assign(
        {
          storefront: storefrontScenario('storefrontMix'),
          graphql: storefrontScenario('graphqlMix'),
          crawler: storefrontScenario('crawler'),
        },
        varnishScenario,
        withAdmin ? { admin: adminScenario() } : {}
      );
  }
}

const quiet = ['cleanup'].includes(cfg.profile);
const runsVarnishChecks =
  ['combined', 'graphql', 'storefront'].includes(cfg.profile) ||
  (cfg.profile === 'smoke' && cfg.smokeGroups.includes('varnish'));

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
        magento_page_duration: ['p(95)<30000'],
        // every cache behaviour check must pass, however many other requests the run makes
        ...(runsVarnishChecks ? { 'checks{suite:varnish}': ['rate==1'] } : {}),
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
  let boot = { customers: [], admin: null, k6Products: [] };
  if (hasAdmin()) {
    const wantAdminUsers = cfg.profile !== 'storefront' && cfg.adminVus > 0;
    // Simples own their stock directly; configurables carry it on child variant SKUs.
    const catalogSkus = [...catalog.simples.map((p) => p.sku), ...catalog.variantSkus];
    boot = bootstrap(catalog.regionId, wantAdminUsers, catalogSkus);
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
  const key = weighted(storefrontWeights(data));
  runIteration(`web ${key}`, () => WEB_FLOWS[key](data));
}

export function graphqlMix(data) {
  const key = weighted(storefrontWeights(data));
  runIteration(`graphql ${key}`, () => GRAPHQL_FLOWS[key](data));
}

export function adminMix(data) {
  const key = weighted(mix.admin);
  runIteration(`admin ${key}`, () => adminFlow(data, key));
}

export function crawler(data) {
  runIteration('crawler', () => crawl(data));
}

export function varnish(data) {
  runIteration('varnish', () => varnishChecks(data));
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
  // each flow is its own runIteration, so one failing flow doesn't abort the rest
  if (run('varnish')) runIteration('varnish', () => varnishChecks(data));
  for (const key of run('web') ? Object.keys(WEB_FLOWS) : []) {
    if (CUSTOMER_FLOWS.includes(key) && !hasCustomers) continue;
    http.cookieJar().clear(cfg.baseUrl);
    if (key === 'search') ['quick', 'quick_filter', 'advanced'].forEach((k) => runIteration(`web search ${k}`, () => web.search(data, k)));
    else runIteration(`web ${key}`, () => WEB_FLOWS[key](data));
  }
  for (const key of run('graphql') ? Object.keys(GRAPHQL_FLOWS) : []) {
    if (CUSTOMER_FLOWS.includes(key) && !hasCustomers) continue;
    if (key === 'search') ['quick', 'quick_filter'].forEach((k) => runIteration(`graphql search ${k}`, () => gq.gqlSearch(data, k)));
    else runIteration(`graphql ${key}`, () => GRAPHQL_FLOWS[key](data));
  }
  if (run('admin') && data.admin) {
    for (const key of Object.keys(ADMIN_FLOWS)) {
      http.cookieJar().clear(cfg.baseUrl);
      runIteration(`admin ${key}`, () => adminFlow(data, key));
    }
  }
}

// Used when the script is run with plain --vus/--duration flags.
export default function (data) {
  if (cfg.profile === 'crawler') crawler(data);
  else if (cfg.profile === 'graphql') graphqlMix(data);
  else storefrontMix(data);
}
