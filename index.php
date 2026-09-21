<?php
declare(strict_types=1);

// This is a diagnostic test page for the /admin/ URI.
// It intentionally performs no administrative actions.

function h(?string $value): string {
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$forwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
if ($forwardedFor) {
    $chain = array_map('trim', explode(',', $forwardedFor));
    $clientIp = $chain[0] ?: $clientIp;
}

$proto = $_SERVER['HTTP_X_FORWARDED_PROTO']
    ?? ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
$host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'unknown';
$uri = $_SERVER['REQUEST_URI'] ?? '/admin/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$headers = function_exists('getallheaders') ? (getallheaders() ?: []) : [];

// Useful response headers for WAF, proxy, and browser testing.
header('X-L7Tester-Page: admin');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; base-uri 'none'; frame-ancestors 'none'");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>L7 Tester Admin URI</title>
<style>
:root {
  --bg:#0a0c10; --surface:#111318; --border:#1e2330; --accent:#00e5ff;
  --pass:#10b981; --text:#e2e8f0; --muted:#64748b;
  --mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;
  --sans:Inter,Segoe UI,Arial,sans-serif;
}
* { box-sizing:border-box; margin:0; padding:0; }
body { min-height:100vh; background:var(--bg); color:var(--text); font:13px/1.6 var(--mono); }
body::before { content:""; position:fixed; inset:0; pointer-events:none; background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,.015) 2px,rgba(0,229,255,.015) 4px); }
header { padding:2rem; border-bottom:1px solid var(--border); display:flex; align-items:baseline; gap:1rem; flex-wrap:wrap; }
h1 { font:800 1.6rem/1 var(--sans); color:#fff; }
h1 span { color:var(--accent); }
.tagline { color:var(--muted); font-size:11px; letter-spacing:.1em; text-transform:uppercase; }
main { width:min(1100px,calc(100% - 2rem)); margin:2rem auto; }
.hero { border:1px solid var(--border); background:linear-gradient(135deg,rgba(0,229,255,.06),rgba(124,58,237,.05)); padding:1.5rem; margin-bottom:1rem; }
.eyebrow { color:var(--accent); font-size:10px; text-transform:uppercase; letter-spacing:.14em; margin-bottom:.4rem; }
.hero h2 { font:700 1.4rem/1.2 var(--sans); margin-bottom:.5rem; }
.hero p { color:var(--muted); max-width:760px; }
.badge { display:inline-block; margin-top:1rem; padding:.2rem .55rem; color:var(--pass); background:rgba(16,185,129,.13); font-size:10px; font-weight:700; letter-spacing:.07em; }
.grid { display:grid; grid-template-columns:1fr 1fr; gap:1rem; }
.card { border:1px solid var(--border); background:var(--surface); }
.card h3 { padding:.65rem .85rem; border-bottom:1px solid var(--border); font:700 .72rem/1 var(--sans); text-transform:uppercase; letter-spacing:.1em; }
table { width:100%; border-collapse:collapse; }
tr { border-bottom:1px solid var(--border); }
tr:last-child { border-bottom:0; }
td { padding:.45rem .85rem; vertical-align:top; word-break:break-word; }
td:first-child { width:38%; color:var(--muted); white-space:nowrap; }
a { color:var(--accent); }
footer { padding:1.5rem; text-align:center; color:var(--muted); border-top:1px solid var(--border); font-size:10px; text-transform:uppercase; letter-spacing:.1em; }
@media (max-width:800px) { .grid { grid-template-columns:1fr; } td:first-child { white-space:normal; } }
</style>
</head>
<body>
<header>
  <h1>L7<span>TESTER</span></h1>
  <span class="tagline">Admin URI diagnostic endpoint</span>
</header>
<main>
  <section class="hero">
    <div class="eyebrow">Route status</div>
    <h2>/admin/ is reachable</h2>
    <p>This page is a harmless diagnostic endpoint for testing path-based routing, redirects, reverse proxies, and WAF rules. It does not expose administrative controls.</p>
    <span class="badge">HTTP <?= h($_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1') ?> · <?= h($method) ?></span>
  </section>

  <div class="grid">
    <section class="card">
      <h3>Request details</h3>
      <table>
        <tr><td>Method</td><td><?= h($method) ?></td></tr>
        <tr><td>URI</td><td><?= h($uri) ?></td></tr>
        <tr><td>Full URL</td><td><?= h($proto . '://' . $host . $uri) ?></td></tr>
        <tr><td>Client IP</td><td><?= h($clientIp) ?></td></tr>
        <tr><td>Protocol</td><td><?= h($_SERVER['SERVER_PROTOCOL'] ?? 'N/A') ?></td></tr>
        <tr><td>Server time</td><td><?= h(date('Y-m-d H:i:s T')) ?></td></tr>
        <tr><td>PHP version</td><td><?= h(PHP_VERSION) ?></td></tr>
        <?php if ($forwardedFor): ?>
        <tr><td>X-Forwarded-For</td><td><?= h($forwardedFor) ?></td></tr>
        <?php endif; ?>
      </table>
    </section>

    <section class="card">
      <h3>Inbound headers</h3>
      <table>
        <?php if (!$headers): ?>
        <tr><td>Status</td><td>No headers exposed by the runtime.</td></tr>
        <?php else: ?>
          <?php foreach ($headers as $name => $value): ?>
          <tr><td><?= h((string)$name) ?></td><td><?= h(is_array($value) ? implode(', ', $value) : (string)$value) ?></td></tr>
          <?php endforeach; ?>
        <?php endif; ?>
      </table>
    </section>
  </div>

  <p style="margin-top:1rem"><a href="/">← Return to L7 Tester</a></p>
</main>
<footer>l7tester.com · /admin/ diagnostic page · PHP <?= h(PHP_VERSION) ?></footer>
</body>
</html>
