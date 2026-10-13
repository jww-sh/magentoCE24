# Magento 2 Community Edition for Upsun FLEX

This template builds Magento 2.4.9+ CE on Platform.sh and Upsun.  It includes the Magento ECE-Tools to run effectively in a build-and-deploy environment.  A MariaDB Database, Opensearch Indexer, ActiveMQ Message Queue and Valkey Cache server come pre-configured and work out of the box. 

Magento is a fully integrated ecommerce system and web store written in PHP.  This is the Open Source version of Magento.

## Features

* PHP 8.5
* MariaDB 12.3
* Valkey 9.0
* Opensearch 3
* ActiveMQ Artemis 2
* Composer-based build

## Composer Authentication and Post Installation Setup

1. Get your Magento Repository authentication keys https://devdocs.magento.com/guides/v2.4/install-gde/prereq/connect-auth.html if you want to adjust the composer repo to https://repo.magento.com/
2. Add your keys as a project level variable `upsun variable:create -p <your Platform.sh projectID> --level project --name env:COMPOSER_AUTH --json true --visible-runtime false --sensitive true --visible-build true  --value '{"http-basic":{"repo.magento.com":{"username":"<your public key>","password":"<your private key>"}}}'`
3. Please disable Magento two factor auth for admin logins on development enviroments with mail disabled, please SSH into your application and run `bin/magento config:set twofactorauth/general/enable 0` 
4. Please add an admin user using `php bin/magento admin:user:create`.  Login at `/admin` in your browser. 

## Customizations

If using this project as a reference for your own existing project, replicate the changes below to your project.

* The `.upsun/config.yaml` files has been added. This provides Upsun-specific configuration which can also be reviewed.
* Magento crons have been setup to ensure they are run sequentially to ensure there is availible memory
* A logrotate and report housekeeping cron have been added.
* A module which allows two factor authentication to be disabled has been added to `composer.json`.

## Load Testing

The `testing/k6/` directory contains a k6 load test suite modelled on the Magento Performance Toolkit benchmark.

> **WARNING: Never run these tests against a production site.**
>
> The test suite makes permanent, wide-ranging changes to the Magento database:
>
> - **Customers** — creates up to `CUSTOMER_COUNT` (default: equal to `VUS`) real customer accounts with addresses.
> - **Orders** — places real guest and customer orders through the full checkout flow, consuming stock and creating order records that cannot be deleted via the API (only cancelled).
> - **Stock levels** — resets inventory quantities on all discovered catalog products to 10,000 units at the start of every run.
> - **Admin users** — creates one admin account per admin VU (`k6mlt-admin-N`) unless `ADMIN_SHARE_ACCOUNT=1`.
> - **Products** — creates hidden simple products for admin edit flows.
> - **Search terms** — adds every configured search term to the search term table.
> - **Sessions & carts** — generates large numbers of guest quote records and customer sessions.
>
> Running this against a live store will corrupt real customer data, destroy real stock levels, flood the order grid with test orders, and may cause the site to behave incorrectly for real shoppers.
>
> **Always run load tests on a dedicated staging or development environment with no real customer data.**
>
> Run `PROFILE=cleanup` after testing to cancel orders, restore shipped stock, and remove test data. Some data (orders, quote records, visitor logs) requires the companion `testing/k6/cleanup-orders.php` script to be deleted from the database directly.

## References

* [Adobe Commerce Docs](https://experienceleague.adobe.com/en/docs/commerce)
* [PHP on Platform.sh](https://docs.platform.sh/languages/php.html)
