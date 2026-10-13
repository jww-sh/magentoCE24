// Setup-time catalog discovery via the public GraphQL API, so storefront flows
// don't need admin access. Replaces the JMX setUp REST product/category harvest.
import http from 'k6/http';
import { cfg, PREFIX } from './config.js';
import { baseHeaders, url } from './http.js';

export function gql(query, variables, extraHeaders, name) {
  const res = http.post(url('graphql'), JSON.stringify({ query, variables: variables || {} }), {
    headers: Object.assign(baseHeaders(), { 'Content-Type': 'application/json', Accept: 'application/json' }, extraHeaders || {}),
    tags: { name: name || 'GraphQL' },
  });
  let body = null;
  try {
    body = res.json();
  } catch (e) {
    body = null;
  }
  return { res, body, data: body && body.data, errors: body && body.errors };
}

const PRODUCTS_QUERY = `query($page:Int!,$size:Int!){
  products(search:"", filter:{}, pageSize:$size, currentPage:$page){
    total_count
    page_info{ total_pages }
    items{
      __typename id sku name url_key stock_status
      price_range{ minimum_price{ regular_price{ value } } }
      ... on CustomizableProductInterface { options { required } }
      ... on ConfigurableProduct {
        configurable_options{ attribute_id_v2 attribute_code }
        variants{ attributes{ code value_index } product{ stock_status sku } }
      }
    }
  }
}`;

const CATEGORIES_QUERY = `{
  categoryList(filters:{}){
    children{ id name url_path product_count
      children{ id name url_path product_count
        children{ id name url_path product_count } } }
  }
}`;

function flattenCategories(nodes, out) {
  for (const c of nodes || []) {
    if (c.product_count > 0 && c.url_path && !c.name.startsWith(PREFIX)) {
      out.push({ id: c.id, name: c.name, path: c.url_path });
    }
    flattenCategories(c.children, out);
  }
  return out;
}

export function discover() {
  const sc = gql('{ storeConfig { product_url_suffix category_url_suffix } }').data;
  const productSuffix = sc ? sc.storeConfig.product_url_suffix || '' : '.html';
  const categorySuffix = sc ? sc.storeConfig.category_url_suffix || '' : '.html';

  const catData = gql(CATEGORIES_QUERY).data;
  const categories = flattenCategories(catData ? catData.categoryList[0].children : [], []).map((c) => ({
    id: c.id,
    name: c.name,
    url: `${c.path}${categorySuffix}`,
  }));

  const simples = [];
  const configurables = [];
  const size = 100;
  let page = 1;
  let pages = 1;
  while (page <= pages && simples.length + configurables.length < cfg.maxProducts) {
    const r = gql(PRODUCTS_QUERY, { page, size });
    if (!r.data) {
      console.error(`Product discovery failed on page ${page}: ${JSON.stringify(r.errors || r.res.status)}`);
      break;
    }
    pages = r.data.products.page_info.total_pages;
    for (const p of r.data.products.items) {
      if (p.stock_status !== 'IN_STOCK' || p.sku.startsWith(PREFIX)) continue;
      const base = {
        id: p.id,
        sku: p.sku,
        name: p.name,
        urlKey: p.url_key,
        url: `${p.url_key}${productSuffix}`,
        price: p.price_range.minimum_price.regular_price.value,
      };
      if (p.__typename === 'SimpleProduct' && !(p.options || []).some((o) => o.required)) {
        simples.push(base);
      } else if (p.__typename === 'ConfigurableProduct') {
        const variant = (p.variants || []).find((v) => v.product && v.product.stock_status === 'IN_STOCK');
        if (!variant) continue;
        const superAttributes = {};
        for (const opt of p.configurable_options) {
          const a = variant.attributes.find((x) => x.code === opt.attribute_code);
          if (a) superAttributes[opt.attribute_id_v2] = a.value_index;
        }
        // collect all in-stock variant SKUs — MSI stock lives on children, not the parent
        const variantSkus = (p.variants || [])
          .filter((v) => v.product && v.product.stock_status === 'IN_STOCK' && v.product.sku)
          .map((v) => v.product.sku);
        configurables.push(Object.assign(base, { superAttributes, variantSkus }));
      }
    }
    page++;
  }

  const regionData = gql(`{ country(id:"${cfg.address.countryId}"){ available_regions{ id code } } }`).data;
  const regions = {};
  for (const r of (regionData && regionData.country && regionData.country.available_regions) || []) {
    regions[r.code] = r.id;
  }

  if (categories.length === 0 || simples.length === 0 || configurables.length === 0) {
    console.warn(
      `Discovery found ${categories.length} categories, ${simples.length} simple, ${configurables.length} configurable products`
    );
  }

  const variantSkus = configurables.flatMap((c) => c.variantSkus || []);
  return { categories, simples, configurables, variantSkus, regionId: regions[cfg.address.regionCode] || null };
}
