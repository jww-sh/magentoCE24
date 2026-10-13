// Runtime configuration, read once from __ENV.
// Every value can be passed with `k6 run -e NAME=value` or, on Upsun, with
// `upsun task:run loadtesting-k6 --variable env:NAME=value`.

function str(name, fallback) {
  const v = __ENV[name];
  return v === undefined || v === '' ? fallback : v;
}

function num(name, fallback) {
  const v = parseFloat(__ENV[name]);
  return Number.isFinite(v) ? v : fallback;
}

function bool(name, fallback) {
  const v = __ENV[name];
  if (v === undefined || v === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

const vus = num('VUS', 10);

export const cfg = {
  // On Upsun the loadtesting-k6 task gets URL from the primary route (see .upsun/config.yaml)
  baseUrl: str('URL', '').replace(/\/$/, ''),
  profile: str('PROFILE', 'combined'),
  debug: bool('DEBUG', false),

  // Load shape (storefront scenario)
  vus,
  duration: str('DURATION', '10m'),
  rampUp: str('RAMP', '1m'),
  rampDown: str('RAMP_DOWN', '30s'),
  rps: num('RPS', 0),

  // Think time between page requests, mirrors JMX think_time_delay_offset/deviation
  thinkMs: num('THINK_MS', 2000),
  thinkDeviationMs: num('THINK_DEVIATION_MS', 1000),

  // FPC=OFF appends a cache-busting query param to every storefront GET
  fpcBust: str('FPC', 'ON').toUpperCase() === 'OFF',

  // Optional HTTP basic auth in front of the site (e.g. staging envs)
  basicAuthUser: str('BASIC_AUTH_USER', str('USERNAME', '')),
  basicAuthPassword: str('BASIC_AUTH_PASSWORD', str('PASSWORD', '')),

  // The single credential pair everything else is bootstrapped from
  adminPath: str('ADMIN_PATH', 'admin'),
  adminUser: str('ADMIN_USER', ''),
  adminPassword: str('ADMIN_PASSWORD', ''),
  adminRoleId: str('ADMIN_ROLE_ID', '1'),
  adminVus: num('ADMIN_VUS', 1),
  // Use the main admin account for every admin VU instead of k6mlt-admin-N users.
  // Only safe when admin/security/admin_account_sharing=1.
  adminShareAccount: bool('ADMIN_SHARE_ACCOUNT', false),

  customerCount: num('CUSTOMER_COUNT', Math.max(20, vus * 3)),
  maxProducts: num('MAX_PRODUCTS', 400),
  searchTerms: str('SEARCH_TERMS', 'bag,jacket,shirt,pants,watch,yoga,tee,short,hoodie,bra,small,medium,large,extra large,plus size,petite,regular,XXL,black,white,red,blue,green,gray,navy,purple,pink,orange,yellow,brown,silver,gold,coral,teal,maroon,olive,khaki,cream,beige,charcoal,burgundy,turquoise,lavender,mint,stripe,plaid,fleece,cotton,wool,denim,running,training,sport,casual,slim,fitted,relaxed,women,men,kids,vest,skirt,dress,coat,blazer,cardigan,leggings,polo,sweater,jeans,chinos,scarf,cap,boots,sneakers,sandals,blouse,tunic,jumpsuit,tank top,swimsuit').split(','),

  // Address used for checkout and seeded customers (JMX defaults)
  address: {
    countryId: str('ADDRESS_COUNTRY', 'US'),
    regionCode: str('ADDRESS_REGION_CODE', 'CA'),
    region: str('ADDRESS_REGION', 'California'),
    street: str('ADDRESS_STREET', '10441 Jefferson Blvd ste 200'),
    city: str('ADDRESS_CITY', 'Culver City'),
    postcode: str('ADDRESS_POSTCODE', '90232'),
    telephone: str('ADDRESS_TELEPHONE', '3109450345'),
  },
  paymentMethod: str('PAYMENT_METHOD', 'checkmo'),
  shippingCarrier: str('SHIPPING_CARRIER', 'flatrate'),
  shippingMethod: str('SHIPPING_METHOD', 'flatrate'),

  // PROFILE=smoke: which flow groups to run (web, graphql, admin, varnish)
  smokeGroups: str('SMOKE_GROUPS', 'web,graphql,admin,varnish').split(',').map((g) => g.trim()),

  // Max failure records (full request/response) each VU writes to the report
  failureLogLimit: num('FAILURE_LOG_LIMIT', 50),

  // Crawler profile (original magento.js)
  maxDepth: num('MAX_DEPTH', 5),
  crawlerSleep: num('SLEEP', 1),

  // Cleanup profile toggles
  cleanupCustomers: bool('CLEANUP_CUSTOMERS', false),
  cleanupAdmins: bool('CLEANUP_ADMINS', false),
  // SKUs whose stock was already corrected by hand; the shipped-stock restore skips them
  cleanupStockSkip: str('CLEANUP_STOCK_SKIP', '').split(',').map((s) => s.trim()).filter(Boolean),
};

// Tag on everything k6 creates (emails, SKUs, names, usernames) so it can be found
// and removed. Deliberately free of SQL LIKE wildcards (_ and %) so a search can't
// match anything else. TEST_PREFIX only exists to clean up data from older runs.
export const PREFIX = str('TEST_PREFIX', 'k6mlt');

// tagged('user', 1) -> 'k6mlt-user-1'
export function tagged(kind, ...parts) {
  return [PREFIX, kind, ...parts].join('-');
}

// Domain for every address k6 creates; .local never resolves, so mail can't go anywhere.
export const EMAIL_DOMAIN = str('EMAIL_DOMAIN', 'example.local');

// taggedEmail('user', 1) -> 'k6mlt-user-1@example.local'
export function taggedEmail(kind, ...parts) {
  return `${tagged(kind, ...parts)}@${EMAIL_DOMAIN}`;
}

// Iteration mix, from the JMX "Combined Benchmark Pool" c* properties.
// Override any weight with -e PCT_<KEY>=n (e.g. PCT_GUEST_CHECKOUT=10).
const STOREFRONT_DEFAULTS = {
  browse: 29,
  search: 29,
  add_to_cart: 26,
  guest_checkout: 3.5,
  customer_checkout: 3.5,
  wishlist: 1.5,
  compare: 1.5,
  account: 1,
};

const SEARCH_DEFAULTS = { quick: 60, quick_filter: 30, advanced: 10 };

const ADMIN_DEFAULTS = {
  cms: 0.35,
  product_grid: 0.2,
  order_grid: 0.2,
  customer_grid: 0.1,
  create_product: 0.5,
  edit_product: 0.65,
  returns: 0.75,
  create_order: 0.5,
  category: 0.15,
  promo: 0.2,
  customer_mgmt: 0.4,
  edit_order: 1,
};

function withOverrides(defaults) {
  const out = {};
  for (const key of Object.keys(defaults)) {
    out[key] = num(`PCT_${key.toUpperCase()}`, defaults[key]);
  }
  return out;
}

export const mix = {
  storefront: withOverrides(STOREFRONT_DEFAULTS),
  search: withOverrides(SEARCH_DEFAULTS),
  admin: withOverrides(ADMIN_DEFAULTS),
};

if (!/^https?:\/\//.test(cfg.baseUrl)) {
  throw new Error(`URL must be set to the shop's address, e.g. -e URL=https://shop.example (got "${cfg.baseUrl}")`);
}

export function hasAdmin() {
  return cfg.adminUser !== '' && cfg.adminPassword !== '';
}
