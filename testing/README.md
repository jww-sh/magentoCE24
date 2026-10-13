# Magento load testing (k6)

> ⚠️ **DO NOT RUN AGAINST A PRODUCTION SITE.**
>
> This test suite makes destructive, wide-ranging changes to the Magento database that
> cannot be fully reversed through the API alone:
>
> - **Stock levels** are reset to 10,000 units on every discovered catalog product at the
>   start of every run — overwriting real stock figures permanently.
> - **Real orders** are placed through the full checkout flow (guest and customer),
>   consuming stock, incrementing order number sequences, and creating order records that
>   Magento Open Source cannot delete via REST (only cancel).
> - **Customer accounts** (`k6mlt-user-N@example.local`) and **admin users**
>   (`k6mlt-admin-N`) are created in the live database.
> - **Guest carts, sessions, visitor logs and search terms** are generated in large
>   numbers under load.
> - **Admin flows** invoice, ship and refund k6 orders — triggering real MSI stock
>   movements and email queuing.
>
> Running this against a live store will corrupt real stock levels, pollute the order
> grid and customer list, and may degrade the experience for real shoppers while the
> test is running. **Always use a dedicated staging or development environment with no
> real customer data.** Run `PROFILE=cleanup` followed by `cleanup-orders.php` after
> every test run to remove as much test data as possible (see Cleanup below).

`k6/` is a k6 port of Magento's Performance Toolkit plan (`benchmark.jmx`), plus the
original random-walk crawler (`magento.js`). It runs locally or as the on-demand
Upsun task `k6` (see `tasks:` in `.upsun/config.yaml`), so load is generated from
its own container instead of competing for CPU with the `app` container.

## What's ported

| JMX (Combined Benchmark Pool)           | k6 flow (`PCT_*` key)              | Default % |
| --------------------------------------- | ---------------------------------- | --------- |
| Catalog Browsing By Guest               | `browse`                           | 29        |
| Site Search (quick / filtered / advanced) | `search` (`quick`, `quick_filter`, `advanced`) | 29 (60/30/10) |
| Add To Cart By Guest                    | `add_to_cart`                      | 26        |
| Checkout By Guest                       | `guest_checkout`                   | 3.5       |
| Checkout By Customer                    | `customer_checkout`                | 3.5       |
| Add to Wishlist                         | `wishlist`                         | 1.5       |
| Compare Products                        | `compare`                          | 1.5       |
| Account management                      | `account`                          | 1         |
| Admin CMS / grids / create+edit product / create+edit order / returns / category / promo rules / customer mgmt | admin mix (`cms`, `product_grid`, `order_grid`, `customer_grid`, `create_product`, `edit_product`, `create_order`, `edit_order`, `returns`, `category`, `promo`, `customer_mgmt`) | JMX `c*` values |
| GraphQL Combined Benchmark Pool         | `PROFILE=graphql` (same mix over GraphQL) |      |
| setUp Thread Group                      | `setup()`: GraphQL catalog discovery + bootstrap | |

Not ported: REST API pool, import/export, one-thread scenarios, Admin "Create Product"
bundle/configurable variants (k6 creates a simple product), wishlist "send by email".

### Production-safety deviations
Everything k6 creates is tagged **`k6mlt-`** (k6 Magento load test): emails
`k6mlt-user-N@example.local` / `k6mlt-guest-…@example.local`, SKUs `k6mlt-simple-N`
/ `k6mlt-product-…`, `k6mlt-cms-…`, `k6mlt-category-…`, `k6mlt-rule-…`, admin users
`k6mlt-admin-N`. The tag contains no SQL `LIKE` wildcards (`_`, `%`), so cleanup
searches can't match anything else, and every match is re-checked before deleting.
`.local` addresses never resolve, so no mail leaves the store (`EMAIL_DOMAIN` to change).

Admin flows only **modify** k6-owned data: edit product → hidden `k6mlt-simple-N`
(an admin product save clears every field the request omits, so catalog products are
never re-saved), customer management → `k6mlt-user-N`, edit order / returns →
pending orders placed by `k6mlt-` emails (re-checked on the order page before
invoicing/refunding). Created CMS pages, categories and cart rules are inactive;
created products are "Not Visible Individually".

## One credential
Only `ADMIN_USER` / `ADMIN_PASSWORD` are needed. `setup()` uses them to:
- get a REST admin token (needs admin 2FA off for API tokens, set in `.upsun/config.yaml`)
- create `CUSTOMER_COUNT` customers `k6mlt-user-N@example.local` with an address
- create `ADMIN_VUS` admin users `k6mlt-admin-N` (Magento allows one session per admin
  user, so each admin VU gets its own). Skip with `ADMIN_SHARE_ACCOUNT=1` if
  `admin/security/admin_account_sharing=1`.
- create a few hidden `k6mlt-simple-N` products for the edit-product flow

All of it is idempotent and reused by later runs. The k6 users' password is derived
from `ADMIN_PASSWORD`; if you change the admin password, run `PROFILE=cleanup` with
`CLEANUP_CUSTOMERS=1 CLEANUP_ADMINS=1` first (before changing it) so they are recreated.

Admin "Add Secret Key to URLs" stays on: keys are harvested from admin pages as
the flows navigate (`lib/admin.js`).

Without admin credentials only guest storefront/GraphQL flows run.

## Prerequisites (once)
1. Deploy this branch. It turns admin 2FA (`CONFIG__DEFAULT__TWOFACTORAUTH__*`) and
   the admin login CAPTCHA (`CONFIG__DEFAULT__ADMIN__CAPTCHA__ENABLE`) off, and enables
   the `lz4` PHP extension that `.magento.env.yaml` session compression needs (without
   it every session over 2 KB, i.e. every admin login, fails with a 500).
2. Create the admin user k6 logs in with:
   `upsun ssh -e main --app app -- php bin/magento admin:user:create --admin-user=k6 --admin-password='...' --admin-email=k6@example.local --admin-firstname=K6 --admin-lastname=Bench`
3. Store the credentials as sensitive env vars (visible to the task):
   ```
   upsun variable:create -e main --level environment --name env:ADMIN_USER --value k6 --visible-build false
   upsun variable:create -e main --level environment --name env:ADMIN_PASSWORD --value '...' --sensitive true --visible-build false
   ```
4. Check money/shipping: checkmo and flatrate must be enabled (Magento defaults).

## Running on Upsun
```
upsun task:run loadtesting-k6 -e main --variable env:PROFILE=smoke --wait                      # functional check
upsun task:run loadtesting-k6 -e main --variable env:VUS=30 --variable env:DURATION=15m --wait # combined load
upsun task:run loadtesting-k6 -e main --variable env:PROFILE=graphql --variable env:VUS=30 --wait
upsun task:run loadtesting-k6 -e main --variable env:PROFILE=cleanup --wait
```
Size the task container with `upsun resources:set --size loadtesting-k6:<size>` (1 CPU is fine
for a few dozen VUs; k6 warns when it is CPU-bound). Default timeout is 2h.

Output is in the activity log, and `report.html` (k6 web dashboard; needs runs of
more than ~30s), `summary.json` and `k6.log` are written to `/app/var/k6-reports/<timestamp>-<profile>/`
(`latest` symlink) in the app container. They are browsable at
**`https://<shop domain>/k6-reports/`**: `testing/k6/web/index.php` lists the runs and
serves only those three files from that directory (no caching, `noindex`). It has no
access control of its own, so put some in front of it. Reports contain no passwords:
`setup()` only returns usernames/emails and VUs derive passwords themselves.
```
upsun ssh -e main --app app -- ls var/k6-reports/latest
upsun scp -e main --app app remote:var/k6-reports/latest/report.html .
```

### What each run records
Every run directory (and the `/k6-reports/` index) has:
- `report.html`, `summary.json`, `k6.log`: k6 dashboard, metrics and output
- `run-info.json`: exit code (`99` = thresholds crossed), complete and **interrupted**
  iterations (iterations cut off at the end of the run / ramp-down)
- `failures.jsonl`: one record per failed check or flow exception: scenario, flow, VU,
  iteration, the failed checks, and the **full request** (method, URL, headers, body) and
  **response** (status, network error, headers, first 4 KB of the body, timings). Passwords,
  tokens, form keys and cookie values are masked. Rendered at `/k6-reports/<run>/failures`,
  grouped by flow. `FAILURE_LOG_LIMIT` (default 50) caps records per VU.
- `console.log`: everything else the scripts logged (bootstrap, debug)

The `magento_failed_iterations{flow}` metric counts iterations with a failed check or an exception.

### Varnish checks
`combined`, `graphql`, `storefront` and `smoke` also run a one-off set of full-page-cache
checks against `.upsun/varnish.vcl` (read from `X-Magento-Cache-Debug`): guest pages
MISS→HIT, a different `X-Magento-Vary` gets its own entry, logged-in customers never get
the guest copy, customer/cart/section requests are never cached, GraphQL GET caches per
`X-Magento-Cache-Id` (and per customer with a token), static assets cache with their own
headers. They must all pass (`checks{suite:varnish}` = 100%). `SMOKE_GROUPS=varnish` runs only these.

## Running locally
With k6 v2.3.0 installed (same version as the task):
```
cd testing/k6
k6 run -e URL=https://shop.example -e PROFILE=crawler -e VUS=2 -e DURATION=30s main.js
k6 run -e URL=https://shop.example -e PROFILE=smoke -e THINK_MS=0 \
       -e ADMIN_USER=... -e ADMIN_PASSWORD=... main.js        # every flow once
```

## Variables
| Name | Default | |
| --- | --- | --- |
| `PROFILE` | `combined` | `combined` (storefrontMix + graphqlMix + crawler + varnish + admin), `graphql` (graphqlMix only), `storefront`, `admin`, `crawler`, `smoke`, `cleanup` |
| `SMOKE_GROUPS` | `web,graphql,admin,varnish` | flow groups the smoke profile runs |
| `URL` | primary route on Upsun | required locally, e.g. `-e URL=https://shop.example` |
| `VUS` / `ADMIN_VUS` | `10` / `1` | VUs per scenario / admin VUs. In `combined`, `VUS` drives three parallel scenarios (storefrontMix, graphqlMix, crawler) so total concurrent VUs ≈ 3×VUS + ADMIN_VUS |
| `RAMP` / `DURATION` / `RAMP_DOWN` | `1m` / `10m` / `30s` | |
| `THINK_MS` / `THINK_DEVIATION_MS` | `2000` / `1000` | pause between requests |
| `FPC` | `ON` | `OFF` adds a cache-buster to storefront GETs |
| `PCT_<FLOW>` | see table | override mix weights, e.g. `PCT_GUEST_CHECKOUT=10` |
| `CUSTOMER_COUNT` | `max(20, VUS)` | automatically scaled to VUS so each VU gets its own customer account and carts don't collide |
| `ADMIN_USER` / `ADMIN_PASSWORD` / `ADMIN_PATH` | – / – / `admin` | |
| `SEARCH_TERMS` | `bag,jacket,...` | comma separated |
| `ADDRESS_*`, `PAYMENT_METHOD`, `SHIPPING_CARRIER`, `SHIPPING_METHOD` | US / checkmo / flatrate | checkout data |
| `BASIC_AUTH_USER` / `BASIC_AUTH_PASSWORD` | | HTTP auth in front of the site |
| `MAX_DEPTH` / `SLEEP` | `5` / `1` | crawler |
| `CLEANUP_CUSTOMERS` / `CLEANUP_ADMINS` | off | cleanup also removes k6 customers / admin users |
| `FAILURE_LOG_LIMIT` | `50` | failure records (full request/response) per VU |
| `DEBUG` | off | log failed checks |

## Cleanup
Two steps remove every trace of a test run, in this order:

1. **`PROFILE=cleanup`** (k6, REST + admin only; locally or as the task). Cancels open
   k6 orders, returns the stock their shipments took through MSI (each order gets a
   comment once done, so it never runs twice; `CLEANUP_STOCK_SKIP=sku,…` for SKUs
   corrected by hand), deletes the k6 search terms (Marketing > Search Terms) and the
   k6 products, CMS pages, cart rules and categories. `CLEANUP_CUSTOMERS=1
   CLEANUP_ADMINS=1` also removes the reusable customers, `k6mlt-simple-N` products
   and `k6mlt-admin-N` users.
2. **`cleanup-orders.php`** in the app container, for what Open Source has no API for.
   Uses Magento's own services only: the reservation cleanup job (before the orders
   go), the sales repositories to delete k6 orders with their invoices, shipments and
   credit memos (grid rows go with them), the cart repository for carts created in
   the test window, the visitor cleanup job, then reindex, report statistics refresh
   and full-page cache clean. Dry run first, then `--apply`:
   ```
   upsun ssh -e main --app app -- "php -- --since='2026-10-12 00:00:00'" < testing/k6/cleanup-orders.php
   upsun ssh -e main --app app -- "php -- --since='2026-10-12 00:00:00' --apply" < testing/k6/cleanup-orders.php
   ```
   `--prefix=k6_` cleans data from runs before the `k6mlt-` tag.

Not covered: order/invoice number sequences (can't be rewound safely, so numbers
continue after the gap), the `ADMIN_USER`/`ADMIN_PASSWORD` environment variables, the
admin user itself, `/app/var/k6-reports`, and web/PHP access logs.
