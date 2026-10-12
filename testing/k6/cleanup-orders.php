<?php
/**
 * Second cleanup step after `PROFILE=cleanup` (which cancels k6 orders, returns
 * their shipped stock, deletes k6 customers/products/CMS/rules/search terms/admin
 * users). This removes what Magento Open Source has no API or admin action for,
 * using Magento's own services only (no SQL writes):
 *
 *   1. reservation cleanup (the inventory_cleanup_reservations cron job): drops
 *      reservations that net to zero, i.e. those of cancelled/completed k6 orders.
 *      Must run before the orders are deleted.
 *   2. k6 orders with their credit memos, shipments and invoices, through the sales
 *      repositories (the *_delete_after observers remove the sales grid rows)
 *   3. carts created in the test window by k6 customers, the load generators' IPs
 *      or the APIs (GraphQL/REST carts have no IP), through the cart repository
 *   4. the visitor_clean cron job
 *   5. reindex customer_grid + stock, refresh sales report statistics, clean the FPC
 *
 * Dry run by default; --apply makes the changes. Run in the app container:
 *   upsun ssh -e main --app app -- "php -- --since='2026-10-12 00:00:00'" < testing/k6/cleanup-orders.php
 *   upsun ssh -e main --app app -- "php -- --since='2026-10-12 00:00:00' --apply" < testing/k6/cleanup-orders.php
 *
 * Options: --since=DATETIME (UTC start of the test, required), --ips=a,b,c,
 *          --prefix=TAG (default k6mlt-; k6_ for data from before the k6mlt tag), --apply
 * Not touched: order/invoice number sequences (no safe way to rewind them).
 */

use Magento\Framework\Api\FilterBuilder;
use Magento\Framework\Api\Search\FilterGroupBuilder;
use Magento\Framework\Api\SearchCriteriaBuilder;
use Magento\Framework\App\Bootstrap;

$opts = getopt('', ['since:', 'ips:', 'prefix:', 'apply']);
$apply = isset($opts['apply']);
$since = $opts['since'] ?? null;
if (!$since || !strtotime($since)) {
    fwrite(STDERR, "--since='YYYY-MM-DD HH:MM:SS' (UTC start of the load test) is required\n");
    exit(1);
}
// tag k6 put on its emails; --prefix=k6_ only to clean up runs from before the k6mlt tag
$prefix = $opts['prefix'] ?? 'k6mlt-';
$like = addcslashes($prefix, '\\_%') . '%';
$ips = array_values(array_filter(explode(',', $opts['ips'] ?? '95.211.164.230,63.35.46.240,52.209.117.215')));

$appDir = getenv('PLATFORM_APP_DIR') ?: '/app';
require $appDir . '/app/bootstrap.php';
$om = Bootstrap::create(BP, $_SERVER)->getObjectManager();
$om->get(\Magento\Framework\App\State::class)->setAreaCode('adminhtml');
$om->get(\Magento\Framework\Registry::class)->register('isSecureArea', true);

$criteria = fn() => $om->create(SearchCriteriaBuilder::class);
$filter = fn(string $field, $value, string $type) => $om->create(FilterBuilder::class)
    ->setField($field)->setValue($value)->setConditionType($type)->create();
$isK6 = fn($email) => strncmp((string)$email, $prefix, strlen($prefix)) === 0;
$db = $om->get(\Magento\Framework\App\ResourceConnection::class)->getConnection(); // read-only counts

echo ($apply ? 'APPLYING' : 'DRY RUN (use --apply to change data)') . ", tag '$prefix', window since $since\n\n";

$orderRepo = $om->get(\Magento\Sales\Api\OrderRepositoryInterface::class);
$orders = array_filter(
    $orderRepo->getList($criteria()->addFilter('customer_email', $like, 'like')->create())->getItems(),
    fn($o) => $isK6($o->getCustomerEmail())
);
$orderIds = array_map(fn($o) => (string)$o->getEntityId(), $orders);
echo 'k6 orders: ' . count($orders) . "\n";

// 1. reservations
$countReservations = fn() => (int)$db->fetchOne('SELECT COUNT(*) FROM ' . $db->getTableName('inventory_reservation'));
$before = $countReservations();
if ($apply) {
    $om->get(\Magento\InventoryReservationsApi\Model\CleanupReservationsInterface::class)->execute();
}
printf("1. reservations: %d%s\n", $before, $apply ? ' -> ' . $countReservations() . ' (only unbalanced, i.e. open, orders keep theirs)' : '');

// 2. orders and their documents
$docs = [
    'credit memos' => \Magento\Sales\Api\CreditmemoRepositoryInterface::class,
    'shipments' => \Magento\Sales\Api\ShipmentRepositoryInterface::class,
    'invoices' => \Magento\Sales\Api\InvoiceRepositoryInterface::class,
];
echo "2. orders\n";
foreach ($docs as $label => $repoClass) {
    $repo = $om->get($repoClass);
    $items = $orderIds ? $repo->getList($criteria()->addFilter('order_id', $orderIds, 'in')->create())->getItems() : [];
    if ($apply) {
        foreach ($items as $item) {
            $repo->delete($item);
        }
    }
    printf("   %-14s %d\n", $label, count($items));
}
if ($apply) {
    foreach ($orders as $order) {
        $orderRepo->delete($order);
    }
}
printf("   %-14s %d\n", 'orders', count($orders));

// 3. carts
$cartRepo = $om->get(\Magento\Quote\Api\CartRepositoryInterface::class);
$origin = $om->create(FilterGroupBuilder::class)
    ->addFilter($filter('customer_email', $like, 'like'))
    ->addFilter($filter('remote_ip', $ips, 'in'))
    ->addFilter($filter('remote_ip', true, 'null'))
    ->create();
$window = $om->create(FilterGroupBuilder::class)->addFilter($filter('created_at', $since, 'gteq'))->create();
$carts = $cartRepo->getList($criteria()->setFilterGroups([$origin, $window])->create())->getItems();
if ($apply) {
    foreach ($carts as $cart) {
        $cartRepo->delete($cart);
    }
}
printf("3. carts: %d\n", count($carts));

// 4. visitors (same as the visitor_clean cron job: removes visitors past the online timeout)
$visitorTable = $db->getTableName('customer_visitor');
$visitors = (int)$db->fetchOne("SELECT COUNT(*) FROM $visitorTable");
if ($apply) {
    $om->get(\Magento\Customer\Model\Visitor::class)->clean();
}
printf("4. visitors: %d%s\n", $visitors, $apply ? ' -> ' . (int)$db->fetchOne("SELECT COUNT(*) FROM $visitorTable") : '');

if ($apply) {
    echo "5. reindex, report statistics, full page cache\n";
    $registry = $om->get(\Magento\Framework\Indexer\IndexerRegistry::class);
    foreach (['customer_grid', 'inventory', 'cataloginventory_stock'] as $indexer) {
        $registry->get($indexer)->reindexAll();
    }
    // same report models as Reports > Statistics > Refresh Lifetime Statistics
    foreach ([
        \Magento\Sales\Model\ResourceModel\Report\Order::class,
        \Magento\Tax\Model\ResourceModel\Report\Tax::class,
        \Magento\Sales\Model\ResourceModel\Report\Shipping::class,
        \Magento\Sales\Model\ResourceModel\Report\Invoiced::class,
        \Magento\Sales\Model\ResourceModel\Report\Refunded::class,
        \Magento\SalesRule\Model\ResourceModel\Report\Rule::class,
        \Magento\Sales\Model\ResourceModel\Report\Bestsellers::class,
        \Magento\Reports\Model\ResourceModel\Report\Product\Viewed::class,
    ] as $report) {
        $om->create($report)->aggregate();
    }
    $om->get(\Magento\Framework\App\Cache\TypeListInterface::class)->cleanType('full_page');
    echo "   done\n";
}
