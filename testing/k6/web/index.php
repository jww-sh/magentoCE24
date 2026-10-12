<?php
/**
 * Serves k6 load-test reports from var/k6-reports at /k6-reports (see the
 * "/k6-reports" web location in .upsun/config.yaml). Runs outside Magento:
 * lists the runs and serves report.html / summary.json / k6.log, nothing else.
 * Add access control in front of it before relying on it.
 */

$base = realpath((getenv('PLATFORM_APP_DIR') ?: dirname(__DIR__, 3)) . '/var/k6-reports');

header('Cache-Control: no-store, private');
header('X-Robots-Tag: noindex, nofollow');
header('X-Content-Type-Options: nosniff');

if ($base === false) {
    http_response_code(404);
    exit('No reports yet');
}

// /k6-reports/<run>/<file>; anything else shows the index
$path = trim(substr(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH), strlen('/k6-reports')), '/');
$types = ['html' => 'text/html; charset=utf-8', 'json' => 'application/json', 'log' => 'text/plain; charset=utf-8'];

if ($path !== '') {
    $file = realpath($base . '/' . rawurldecode($path));
    $ext = $file ? strtolower(pathinfo($file, PATHINFO_EXTENSION)) : '';
    // only regular files inside the reports directory, only known report types
    if (!$file || strncmp($file, $base . '/', strlen($base) + 1) !== 0 || !is_file($file) || !isset($types[$ext])) {
        http_response_code(404);
        exit('Not found');
    }
    header('Content-Type: ' . $types[$ext]);
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

$runs = array_filter(scandir($base, SCANDIR_SORT_DESCENDING), fn($d) => $d[0] !== '.' && $d !== 'latest' && is_dir("$base/$d"));
$h = fn($s) => htmlspecialchars($s, ENT_QUOTES);
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>k6 reports</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; margin: 2rem; color: #222; }
  table { border-collapse: collapse; } td, th { padding: .35rem .9rem; border-bottom: 1px solid #ddd; text-align: left; }
  th { font-weight: 600; } a { color: #0b57d0; } .muted { color: #888; }
</style></head>
<body>
<h1>k6 load test reports</h1>
<?php if (!$runs): ?>
  <p class="muted">No runs yet.</p>
<?php else: ?>
<table>
  <tr><th>Run (UTC)</th><th>Profile</th><th>Files</th></tr>
  <?php foreach ($runs as $run):
      [$stamp, $profile] = array_pad(explode('-', $run, 2), 2, ''); ?>
  <tr>
    <td><?= $h(preg_replace('/^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/', '$1-$2-$3 $4:$5:$6', $stamp)) ?></td>
    <td><?= $h($profile) ?></td>
    <td>
      <?php foreach (['report.html' => 'report', 'summary.json' => 'summary', 'k6.log' => 'log'] as $f => $label): ?>
        <?php if (is_file("$base/$run/$f")): ?><a href="/k6-reports/<?= rawurlencode($run) ?>/<?= $f ?>"><?= $label ?></a><?php else: ?><span class="muted"><?= $label ?></span><?php endif ?>
      <?php endforeach ?>
    </td>
  </tr>
  <?php endforeach ?>
</table>
<?php endif ?>
</body>
</html>
