# Magento load testing (k6)

`k6/` is a k6 port of Magento's Performance Toolkit plan (`benchmark.jmx`), plus the
original random-walk crawler (`magento.js`). It runs locally or as the on-demand
Upsun task `k6` (see `tasks:` in `.upsun/config.yaml`), so load is generated from
its own container instead of stealing CPU from the 1-CPU `app` container.

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
Everything k6 creates is prefixed `k6_`. Admin flows only **modify** k6-owned data:
edit product → hidden `k6_simple_N` (an admin product save clears every field the
request omits, so catalog products are never re-saved), customer management →
`k6_user_N@example.com`,
edit order / returns → pending orders placed by `k6_*` emails (re-checked on the
order page before invoicing/refunding). Created CMS pages, categories and cart
rules are inactive; created products are "Not Visible Individually".

## One credential
Only `ADMIN_USER` / `ADMIN_PASSWORD` are needed. `setup()` uses them to:
- get a REST admin token (needs admin 2FA off for API tokens, set in `.upsun/config.yaml`)
- create `CUSTOMER_COUNT` customers `k6_user_N@example.com` with an address
- create `ADMIN_VUS` admin users `k6_admin_N` (Magento allows one session per admin
  user, so each admin VU gets its own). Skip with `ADMIN_SHARE_ACCOUNT=1` if
  `admin/security/admin_account_sharing=1`.
- create a few hidden `k6_simple_N` products for the edit-product flow

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
   `upsun ssh -e main --app app -- php bin/magento admin:user:create --admin-user=k6 --admin-password='...' --admin-email=k6@example.com --admin-firstname=K6 --admin-lastname=Bench`
3. Store the credentials as sensitive env vars (visible to the task):
   ```
   upsun variable:create -e main --level environment --name env:ADMIN_USER --value k6 --visible-build false
   upsun variable:create -e main --level environment --name env:ADMIN_PASSWORD --value '...' --sensitive true --visible-build false
   ```
4. Check money/shipping: checkmo and flatrate must be enabled (Magento defaults).

## Running on Upsun
```
upsun task:run k6 -e main --variable env:PROFILE=smoke --wait                      # functional check
upsun task:run k6 -e main --variable env:VUS=30 --variable env:DURATION=15m --wait # combined load
upsun task:run k6 -e main --variable env:PROFILE=graphql --variable env:VUS=30 --wait
upsun task:run k6 -e main --variable env:PROFILE=cleanup --wait
```
Size the task container with `upsun resources:set --size k6:<size>` (1 CPU is fine
for a few dozen VUs; k6 warns when it is CPU-bound). Default timeout is 2h.

Output is in the activity log, and `report.html` (k6 web dashboard; needs runs of
more than ~30s), `summary.json` and `k6.log` are written to `/app/var/k6-reports/<timestamp>-<profile>/`
(`latest` symlink) in the app container:
```
upsun ssh -e main --app app -- ls var/k6-reports/latest
upsun scp -e main --app app remote:var/k6-reports/latest/report.html .
```

## Running locally
```
./run.sh                                  # crawler, 2 VUs, 30s
./run.sh -e PROFILE=smoke -e THINK_MS=0   # every flow once
```

## Variables
| Name | Default | |
| --- | --- | --- |
| `PROFILE` | `combined` | `combined`, `graphql`, `storefront`, `admin`, `crawler`, `smoke`, `cleanup` |
| `URL` | `https://shop.izinga.za.net` | |
| `VUS` / `ADMIN_VUS` | `10` / `1` | storefront VUs / admin VUs |
| `RAMP` / `DURATION` / `RAMP_DOWN` | `1m` / `10m` / `30s` | |
| `THINK_MS` / `THINK_DEVIATION_MS` | `2000` / `1000` | pause between requests |
| `FPC` | `ON` | `OFF` adds a cache-buster to storefront GETs |
| `PCT_<FLOW>` | see table | override mix weights, e.g. `PCT_GUEST_CHECKOUT=10` |
| `CUSTOMER_COUNT` | `20` | keep ≥ storefront VUs so carts don't collide |
| `ADMIN_USER` / `ADMIN_PASSWORD` / `ADMIN_PATH` | – / – / `admin` | |
| `SEARCH_TERMS` | `bag,jacket,...` | comma separated |
| `ADDRESS_*`, `PAYMENT_METHOD`, `SHIPPING_CARRIER`, `SHIPPING_METHOD` | US / checkmo / flatrate | checkout data |
| `BASIC_AUTH_USER` / `BASIC_AUTH_PASSWORD` | | HTTP auth in front of the site |
| `MAX_DEPTH` / `SLEEP` | `5` / `1` | crawler |
| `CLEANUP_CUSTOMERS` / `CLEANUP_ADMINS` | off | cleanup also removes k6 customers / admin users |
| `DEBUG` | off | log failed checks |

## Cleanup
`PROFILE=cleanup` cancels open k6 orders and deletes k6 products, CMS pages, cart
rules and categories. Magento Open Source cannot delete orders, so invoiced k6
orders remain. Every order/customer/email k6 makes uses an `@example.com` address.
