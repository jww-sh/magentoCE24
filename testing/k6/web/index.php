<?php
/**
 * Serves k6 load-test reports from var/k6-reports at /k6-reports (see the
 * "/k6-reports" web location in .upsun/config.yaml). Runs outside Magento.
 *
 *   /k6-reports/                    runs with result, iterations and failure counts
 *   /k6-reports/<run>/failures      failed checks / exceptions with full request + response
 *   /k6-reports/<run>/<file>        report.html, summary.json, run-info.json, k6.log,
 *                                   console.log, failures.jsonl (nothing else is served)
 *
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

$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES);
$path = trim(substr(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH), strlen('/k6-reports')), '/');
$types = [
    'html' => 'text/html; charset=utf-8',
    'json' => 'application/json',
    'jsonl' => 'text/plain; charset=utf-8',
    'log' => 'text/plain; charset=utf-8',
];

// resolve a path inside the reports directory, or null
$inside = function (string $relative) use ($base): ?string {
    $file = realpath($base . '/' . $relative);
    return $file && strncmp($file, $base . '/', strlen($base) + 1) === 0 ? $file : null;
};

$readJsonLines = function (string $file, int $limit = 1000): array {
    $rows = [];
    $fh = @fopen($file, 'r');
    while ($fh && ($line = fgets($fh)) !== false && count($rows) < $limit) {
        $row = json_decode($line, true);
        if (is_array($row)) {
            $rows[] = $row;
        }
    }
    $fh && fclose($fh);
    return $rows;
};

$page = function (string $title, string $body) use ($h) {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>' . $h($title) . '</title><style>
      body { font: 15px/1.5 system-ui, sans-serif; margin: 2rem; color: #222; }
      table { border-collapse: collapse; } td, th { padding: .35rem .8rem; border-bottom: 1px solid #ddd; text-align: left; vertical-align: top; }
      th { font-weight: 600; } a { color: #0b57d0; } .muted { color: #888; } .bad { color: #b3261e; font-weight: 600; } .ok { color: #1e7e34; }
      details { margin: .2rem 0; } summary { cursor: pointer; }
      pre { background: #f6f8fa; padding: .6rem; overflow-x: auto; max-height: 28rem; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
      code { font-size: 13px; }
    </style></head><body>' . $body . '</body></html>';
};

// --- failures page -----------------------------------------------------------
if (preg_match('#^([^/]+)/failures$#', $path, $m)) {
    $dir = $inside(rawurldecode($m[1]));
    $file = $dir ? $dir . '/failures.jsonl' : null;
    if (!$dir || !is_file($file)) {
        http_response_code(404);
        exit('Not found');
    }
    $rows = $readJsonLines($file);
    $byFlow = [];
    foreach ($rows as $r) {
        $key = (($r['flow'] ?? '') ?: ($r['scenario'] ?? '')) . ' | ' . ($r['name'] ?? '');
        $byFlow[$key] = ($byFlow[$key] ?? 0) + 1;
    }
    arsort($byFlow);
    $pretty = fn($v) => $h(is_string($v) ? $v : json_encode($v, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

    $out = '<p><a href="/k6-reports/">&larr; all runs</a></p><h1>Failures: ' . $h($m[1]) . '</h1>';
    $out .= '<p>' . count($rows) . ' records' . (count($rows) >= 1000 ? ' (first 1000 shown)' : '')
        . ' &middot; <a href="/k6-reports/' . rawurlencode($m[1]) . '/failures.jsonl">raw jsonl</a></p>';
    if ($byFlow) {
        $out .= '<h2>By flow and request</h2><table><tr><th>Flow | request</th><th>Count</th></tr>';
        foreach ($byFlow as $k => $n) {
            $out .= '<tr><td>' . $h($k) . '</td><td>' . $n . '</td></tr>';
        }
        $out .= '</table><h2>Records</h2>';
    }
    $out .= '<table><tr><th>Time / VU</th><th>Flow</th><th>What failed</th><th>Request</th><th>Details</th></tr>';
    foreach ($rows as $r) {
        $req = $r['request'] ?? [];
        $res = $r['response'] ?? [];
        $isException = ($r['type'] ?? '') === 'exception';
        $what = $isException
            ? '<span class="bad">exception</span>: ' . $h($r['message'] ?? '')
            : $h($r['name'] ?? '') . '<br><span class="muted">' . $h(implode('; ', $r['failed'] ?? [])) . '</span>';
        $request = isset($req['url'])
            ? '<code>' . $h(($req['method'] ?? '') . ' ' . $req['url']) . '</code><br>&rarr; <span class="bad">' . $h($res['status'] ?? '') . '</span>'
              . (!empty($res['error']) ? ' ' . $h($res['error']) : '')
              . (isset($res['timings']['duration']) ? ' <span class="muted">' . round($res['timings']['duration']) . ' ms</span>' : '')
            : '';
        $details = $isException
            ? '<details><summary>stack</summary><pre>' . $h($r['stack'] ?? '') . '</pre></details>'
            : '<details><summary>request</summary><pre>' . $pretty($req) . '</pre></details>'
              . '<details><summary>response</summary><pre>' . $pretty(array_diff_key($res, ['body' => 1])) . '</pre>'
              . '<pre>' . $h($res['body'] ?? '') . '</pre></details>';
        $out .= '<tr><td>' . $h($r['time'] ?? '') . '<br><span class="muted">'
            . $h(($r['scenario'] ?? '') . ' vu ' . ($r['vu'] ?? '') . ' it ' . ($r['iteration'] ?? '')) . '</span></td>'
            . '<td>' . $h($r['flow'] ?? '') . '</td><td>' . $what . '</td><td>' . $request . '</td><td>' . $details . '</td></tr>';
    }
    $page('k6 failures ' . $m[1], $out . '</table>');
    exit;
}

// --- single file -------------------------------------------------------------
if ($path !== '') {
    $file = $inside(rawurldecode($path));
    $ext = $file ? strtolower(pathinfo($file, PATHINFO_EXTENSION)) : '';
    // only regular files inside the reports directory, only known report types
    if (!$file || !is_file($file) || !isset($types[$ext])) {
        http_response_code(404);
        exit('Not found');
    }
    header('Content-Type: ' . $types[$ext]);
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

// --- index -------------------------------------------------------------------
$runs = array_filter(scandir($base, SCANDIR_SORT_DESCENDING), fn($d) => $d[0] !== '.' && $d !== 'latest' && is_dir("$base/$d"));
$out = '<h1>k6 load test reports</h1>';
if (!$runs) {
    $page('k6 reports', $out . '<p class="muted">No runs yet.</p>');
    exit;
}
$out .= '<table><tr><th>Run (UTC)</th><th>Profile</th><th>Result</th><th>Iterations</th><th>Failures</th><th>Files</th></tr>';
foreach ($runs as $run) {
    [$stamp, $profile] = array_pad(explode('-', $run, 2), 2, '');
    $info = is_file("$base/$run/run-info.json") ? json_decode(file_get_contents("$base/$run/run-info.json"), true) : null;
    $result = '<span class="muted">n/a</span>';
    $iterations = '<span class="muted">n/a</span>';
    if (is_array($info)) {
        $code = (int)($info['exit_code'] ?? -1);
        $result = $code === 0 ? '<span class="ok">passed</span>'
            : '<span class="bad">' . ($code === 99 ? 'thresholds crossed' : 'failed (exit ' . $code . ')') . '</span>';
        $interrupted = (int)($info['iterations_interrupted'] ?? 0);
        $iterations = (int)($info['iterations_complete'] ?? 0) . ' complete, '
            . ($interrupted ? '<span class="bad">' . $interrupted . ' interrupted</span>' : '0 interrupted');
    }
    $failures = is_file("$base/$run/failures.jsonl") ? count(file("$base/$run/failures.jsonl", FILE_SKIP_EMPTY_LINES)) : null;
    $failCell = $failures === null ? '<span class="muted">n/a</span>'
        : ($failures ? '<a class="bad" href="/k6-reports/' . rawurlencode($run) . '/failures">' . $failures . '</a>' : '0');
    $files = [];
    foreach (['report.html' => 'report', 'summary.json' => 'summary', 'run-info.json' => 'info', 'k6.log' => 'log', 'console.log' => 'console'] as $f => $label) {
        $files[] = is_file("$base/$run/$f")
            ? '<a href="/k6-reports/' . rawurlencode($run) . '/' . $f . '">' . $label . '</a>'
            : '<span class="muted">' . $label . '</span>';
    }
    $out .= '<tr><td>' . $h(preg_replace('/^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/', '$1-$2-$3 $4:$5:$6', $stamp)) . '</td>'
        . '<td>' . $h($profile) . '</td><td>' . $result . '</td><td>' . $iterations . '</td><td>' . $failCell . '</td><td>' . implode(' ', $files) . '</td></tr>';
}
$page('k6 reports', $out . '</table>');
