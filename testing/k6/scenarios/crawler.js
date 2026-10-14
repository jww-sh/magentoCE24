// Random-walk crawler: the original testing/magento.js logic, unchanged apart
// from reading its settings from lib/config.js. Run with PROFILE=crawler.
import http from 'k6/http';
import { parseHTML } from 'k6/html';
import { sleep, check } from 'k6';
import { Trend, Counter } from 'k6/metrics';
import { cfg } from '../lib/config.js';
import { baseHeaders, pageDuration, errorRate } from '../lib/http.js';

const crawlDepthMetric = new Trend('magento_crawl_depth');
const discoveredLinksCounter = new Counter('magento_links_discovered');

// Helper: Normalize extracted hrefs into fully qualified URLs
function cleanUrl(rawHref, baseUrl) {
  if (!rawHref) return null;

  const href = rawHref.trim();

  // Ignore non-HTTP protocols, anchor links, and JavaScript calls
  if (
    href.startsWith('#') ||
    href.startsWith('javascript:') ||
    href.startsWith('mailto:') ||
    href.startsWith('tel:')
  ) {
    return null;
  }

  // Extract base origin (e.g., https://shop.example)
  const baseOrigin = baseUrl.split('/').slice(0, 3).join('/');

  let fullUrl = href;
  if (href.startsWith('//')) {
    fullUrl = `https:${href}`;
  } else if (href.startsWith('/')) {
    fullUrl = `${baseOrigin}${href}`;
  } else if (!href.startsWith('http://') && !href.startsWith('https://')) {
    fullUrl = `${baseOrigin}/${href}`;
  }

  // Ensure the link stays on the target domain
  if (!fullUrl.startsWith(baseOrigin)) {
    return null;
  }

  // Skip URLs with more than 2 query parameters — heavily filtered/paginated pages
  // add noise without meaningful coverage. URLs with 0-2 params are allowed.
  const qMark = fullUrl.indexOf('?');
  if (qMark !== -1) {
    const paramCount = fullUrl.slice(qMark + 1).split('&').filter(Boolean).length;
    if (paramCount > 2) return null;
  }

  // Exclude non-image static assets/media, logout actions, and cart deletions
  // NOTE: Images (.png, .jpg, .jpeg, .gif, .svg, .webp) are ALLOWED to support dynamic image generation testing
  if (
    /\.(css|js|pdf|zip|ico|woff|woff2|ttf)$/i.test(fullUrl) ||
    fullUrl.includes('/customer/account/logout') ||
    fullUrl.includes('/checkout/cart/delete')
  ) {
    return null;
  }

  // Strip query parameters and hash fragments, deduplicate by clean path
  const urlWithoutQuery = fullUrl.split('?')[0].split('#')[0];
  return urlWithoutQuery.replace(/\/$/, '');
}

// Extract valid URLs and dynamic Magento state using DOM + Regex fallbacks
function extractPageMetadata(res, targetBaseUrl) {
  const foundLinks = new Set();
  const bodyText = res.body || '';

  // 1. Try k6 DOM Parser first (scans both anchor links and image src tags)
  try {
    const doc = parseHTML(bodyText);
    doc.find('a[href], img[src]').each((idx, el) => {
      const urlAttr = el.attributes ? (el.attributes.href || el.attributes.src) : null;
      const validUrl = cleanUrl(urlAttr, targetBaseUrl);
      if (validUrl) foundLinks.add(validUrl);
    });
  } catch (e) {
    // Suppress DOM parser failures
  }

  // 2. Regex Fallback: Scan raw HTML for href="..." and src="..." attributes
  const urlRegex = /(?:href|src)=["']([^"']+)["']/gi;
  let match;
  while ((match = urlRegex.exec(bodyText)) !== null) {
    const validUrl = cleanUrl(match[1], targetBaseUrl);
    if (validUrl) {
      foundLinks.add(validUrl);
    }
  }

  // 3. Fallback for Hyvä/JS/JSON paths (e.g., "/media/catalog/product/...")
  const relativePathRegex = /["'](\/[a-zA-Z0-9_\-\/]+\.(?:html|php|jpg|jpeg|png|webp|gif))["']/gi;
  while ((match = relativePathRegex.exec(bodyText)) !== null) {
    const validUrl = cleanUrl(match[1], targetBaseUrl);
    if (validUrl) {
      foundLinks.add(validUrl);
    }
  }

  // 4. Extract dynamic Magento form_key (Input tag or JSON string match)
  let formKey = null;
  const formKeyMatch =
    bodyText.match(/name=["']form_key["']\s+value=["']([^"']+)["']/i) ||
    bodyText.match(/["']formKey["']\s*:\s*["']([^"']+)["']/i);
  if (formKeyMatch) {
    formKey = formKeyMatch[1];
  }

  // 5. Extract Add-To-Cart endpoints
  const addToCartUrls = [];
  const cartRegex = /action=["']([^"']*\/checkout\/cart\/add[^"']*)["']/gi;
  while ((match = cartRegex.exec(bodyText)) !== null) {
    const validAction = cleanUrl(match[1], targetBaseUrl);
    if (validAction) {
      addToCartUrls.push(validAction);
    }
  }

  return {
    links: Array.from(foundLinks),
    formKey: formKey,
    addToCartUrls: addToCartUrls,
  };
}

export function crawl(data) {
  const headers = baseHeaders();
  data = Object.assign({}, data, {
    baseUrl: cfg.baseUrl,
    maxDepth: cfg.maxDepth,
    sleepDelay: cfg.crawlerSleep,
    fpcEnabled: !cfg.fpcBust,
    debug: cfg.debug,
  });

  const visitedUrls = new Set();
  const baseHomepageClean = data.baseUrl.replace(/\/$/, '');

  let currentUrl = data.baseUrl;
  let activeFormKey = null;

  // Crawl loop across up to maxDepth layers
  for (let depth = 1; depth <= data.maxDepth; depth++) {
    // Add cache-buster query parameter if FPC is disabled
    let requestUrl = currentUrl;
    if (!data.fpcEnabled) {
      const separ = requestUrl.includes('?') ? '&' : '?';
      requestUrl = `${requestUrl}${separ}fpc=${__VU}_${__ITER}_d${depth}_${Date.now()}`;
    }

    visitedUrls.add(currentUrl.split('?')[0].replace(/\/$/, ''));

    const res = http.get(requestUrl, { headers, tags: { name: 'Crawl Page' } });

    pageDuration.add(res.timings.duration);
    crawlDepthMetric.add(depth);

    const isOk = check(res, { 'status is 200': (r) => r.status === 200 });
    errorRate.add(!isOk);

    if (res.status !== 200 || !res.body) {
      if (data.debug) {
        console.warn(`[VU ${__VU}] Depth ${depth} failed on ${currentUrl} (Status: ${res.status})`);
      }
      break;
    }

    // Extract dynamic elements from current HTML page
    const metadata = extractPageMetadata(res, data.baseUrl);
    discoveredLinksCounter.add(metadata.links.length);

    if (metadata.formKey) {
      activeFormKey = metadata.formKey;
    }

    // Exclude visited URLs and prevent returning back to the homepage
    const candidateLinks = metadata.links.filter((link) => {
      const isVisited = visitedUrls.has(link);
      const isHomepage = link === baseHomepageClean;
      return !isVisited && !isHomepage;
    });

    if (data.debug) {
      console.log(
        `[VU ${__VU}] Depth ${depth} | Discovered ${metadata.links.length} total links/images | ${candidateLinks.length} new targets available`
      );
    }

    // Dynamic Add-To-Cart trigger if a form is discovered on this page
    if (metadata.addToCartUrls.length > 0 && activeFormKey && Math.random() < 0.3) {
      const cartUrl = metadata.addToCartUrls[Math.floor(Math.random() * metadata.addToCartUrls.length)];

      const payload = {
        form_key: activeFormKey,
        qty: '1',
      };

      const cartRes = http.post(cartUrl, payload, {
        headers: Object.assign({}, headers, {
          'X-Requested-With': 'XMLHttpRequest',
          'Content-Type': 'application/x-www-form-urlencoded',
        }),
      });

      check(cartRes, { 'dynamically added to cart': (r) => r.status === 200 });
    }

    // Stop crawling this branch if no deeper unvisited links were found
    if (candidateLinks.length === 0) {
      if (data.debug) {
        console.log(`[VU ${__VU}] Branch ended at depth ${depth}: No new targets found.`);
      }
      break;
    }

    // Pick a random internal link/image URL to move to the next layer depth
    currentUrl = candidateLinks[Math.floor(Math.random() * candidateLinks.length)];
    sleep(data.sleepDelay);
  }
}
