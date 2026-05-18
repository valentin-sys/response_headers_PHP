<?php
declare(strict_types=1);

// ─── SSRF GUARD ────────────────────────────────────────────────────────────────
function is_safe_url(string $url): array {
    $parsed = parse_url($url);
    if (!$parsed || !isset($parsed['scheme'], $parsed['host'])) {
        return [false, 'Invalid URL format'];
    }
    if (!in_array(strtolower($parsed['scheme']), ['http', 'https'], true)) {
        return [false, 'Only http:// and https:// schemes are allowed'];
    }
    $host = $parsed['host'];
    // Resolve hostname to IPs
    $ips = gethostbynamel($host);
    if ($ips === false || count($ips) === 0) {
        // Try IPv6
        $records = dns_get_record($host, DNS_AAAA);
        if (empty($records)) {
            return [false, 'Could not resolve hostname'];
        }
        $ips = array_column($records, 'ipv6');
    }
    foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return [false, "Resolved IP ($ip) is in a blocked range (private/reserved/loopback)"];
        }
        // Block Azure IMDS explicitly
        if (str_starts_with($ip, '169.254.')) {
            return [false, 'Resolved IP is in a blocked range (link-local)'];
        }
    }
    return [true, ''];
}

// ─── OUTBOUND PROBE ────────────────────────────────────────────────────────────
function probe_url(string $url): array {
    [$safe, $reason] = is_safe_url($url);
    if (!$safe) {
        return ['error' => $reason];
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_HEADER          => true,
        CURLOPT_NOBODY          => false,
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 3,
        CURLOPT_TIMEOUT         => 10,
        CURLOPT_CONNECTTIMEOUT  => 5,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_CERTINFO        => true,
        CURLOPT_USERAGENT       => 'L7Tester/2.0 (+https://l7tester.com)',
        CURLOPT_HTTP_VERSION    => CURL_HTTP_VERSION_2TLS, // prefer HTTP/2
    ]);

    $response   = curl_exec($ch);
    $errno      = curl_errno($ch);
    $error      = curl_error($ch);
    $info       = curl_getinfo($ch);
    $certinfo   = curl_getinfo($ch, CURLINFO_CERTINFO);
    curl_close($ch);

    if ($errno) {
        return ['error' => "cURL error ($errno): $error"];
    }

    // Split headers / body
    $header_size = $info['header_size'];
    $raw_headers = substr($response, 0, $header_size);
    $body_size   = strlen($response) - $header_size;

    // Parse response headers into array
    $header_lines = explode("\r\n", trim($raw_headers));
    $status_line  = array_shift($header_lines);
    $headers      = [];
    foreach ($header_lines as $line) {
        if (str_contains($line, ':')) {
            [$k, $v] = explode(':', $line, 2);
            $headers[strtolower(trim($k))] = trim($v);
        }
    }

    // TLS certificate details from certinfo
    $tls = [];
    if (!empty($certinfo)) {
        $leaf = $certinfo[0] ?? [];
        $tls = [
            'subject'     => $leaf['Subject']     ?? 'N/A',
            'issuer'      => $leaf['Issuer']       ?? 'N/A',
            'start'       => $leaf['Start date']   ?? 'N/A',
            'expire'      => $leaf['Expire date']  ?? 'N/A',
            'chain_depth' => count($certinfo),
            'chain'       => array_map(fn($c) => [
                'subject' => $c['Subject'] ?? '',
                'issuer'  => $c['Issuer']  ?? '',
                'expire'  => $c['Expire date'] ?? '',
            ], $certinfo),
        ];

        // Days until expiry
        if ($tls['expire'] !== 'N/A') {
            $exp = strtotime($tls['expire']);
            $tls['days_remaining'] = $exp ? (int)(($exp - time()) / 86400) : null;
        }
    }

    // Timings in ms
    $timings = [
        'dns_resolve_ms'   => round($info['namelookup_time']  * 1000, 2),
        'tcp_connect_ms'   => round(($info['connect_time'] - $info['namelookup_time']) * 1000, 2),
        'tls_handshake_ms' => round(($info['appconnect_time'] - $info['connect_time']) * 1000, 2),
        'ttfb_ms'          => round(($info['starttransfer_time'] - $info['appconnect_time']) * 1000, 2),
        'total_ms'         => round($info['total_time'] * 1000, 2),
    ];
    // If no TLS, TTFB is relative to connect
    if ($info['appconnect_time'] == 0) {
        $timings['tls_handshake_ms'] = null;
        $timings['ttfb_ms']          = round(($info['starttransfer_time'] - $info['connect_time']) * 1000, 2);
    }

    return [
        'url'            => $info['url'],
        'status_code'    => $info['http_code'],
        'status_line'    => $status_line,
        'http_version'   => match($info['http_version'] ?? 0) {
            CURL_HTTP_VERSION_1_1 => 'HTTP/1.1',
            CURL_HTTP_VERSION_2_0 => 'HTTP/2',
            3                     => 'HTTP/3',
            default               => 'Unknown',
        },
        'ssl_proto'      => $info['ssl_verifyresult'] === 0 ? ($info['ssl_engines'] ?? 'TLS') : 'Verify failed',
        'timings'        => $timings,
        'tls'            => $tls,
        'headers'        => $headers,
        'response_size'  => $body_size,
        'redirect_count' => $info['redirect_count'],
        'effective_url'  => $info['redirect_url'] ?? '',
        'ip'             => $info['primary_ip'],
        'port'           => $info['primary_port'],
    ];
}

// ─── SECURITY HEADER AUDIT ─────────────────────────────────────────────────────
function audit_security_headers(array $headers): array {
    $checks = [
        'strict-transport-security' => [
            'name'    => 'HSTS',
            'desc'    => 'Enforces HTTPS connections',
            'check'   => fn($v) => $v && str_contains($v, 'max-age'),
            'suggest' => 'strict-transport-security: max-age=31536000; includeSubDomains',
        ],
        'content-security-policy' => [
            'name'    => 'CSP',
            'desc'    => 'Controls resource loading to prevent XSS',
            'check'   => fn($v) => (bool)$v,
            'suggest' => "content-security-policy: default-src 'self'",
        ],
        'x-frame-options' => [
            'name'    => 'X-Frame-Options',
            'desc'    => 'Prevents clickjacking via iframes',
            'check'   => fn($v) => in_array(strtoupper($v ?? ''), ['DENY', 'SAMEORIGIN']),
            'suggest' => 'x-frame-options: DENY',
        ],
        'x-content-type-options' => [
            'name'    => 'X-Content-Type-Options',
            'desc'    => 'Prevents MIME sniffing',
            'check'   => fn($v) => strtolower($v ?? '') === 'nosniff',
            'suggest' => 'x-content-type-options: nosniff',
        ],
        'referrer-policy' => [
            'name'    => 'Referrer-Policy',
            'desc'    => 'Controls referrer information leakage',
            'check'   => fn($v) => (bool)$v,
            'suggest' => 'referrer-policy: strict-origin-when-cross-origin',
        ],
        'permissions-policy' => [
            'name'    => 'Permissions-Policy',
            'desc'    => 'Controls browser feature access',
            'check'   => fn($v) => (bool)$v,
            'suggest' => 'permissions-policy: geolocation=(), camera=(), microphone=()',
        ],
        'x-xss-protection' => [
            'name'    => 'X-XSS-Protection',
            'desc'    => 'Legacy XSS filter (deprecated but still checked)',
            'check'   => fn($v) => (bool)$v,
            'suggest' => 'x-xss-protection: 1; mode=block',
        ],
    ];

    $results = [];
    foreach ($checks as $key => $meta) {
        $val = $headers[$key] ?? null;
        $pass = ($meta['check'])($val);
        $results[] = [
            'key'     => $key,
            'name'    => $meta['name'],
            'desc'    => $meta['desc'],
            'pass'    => $pass,
            'value'   => $val,
            'suggest' => $pass ? null : $meta['suggest'],
        ];
    }
    return $results;
}

// ─── INBOUND REQUEST INFO ──────────────────────────────────────────────────────
function get_inbound_info(): array {
    $forwarded_for = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null;
    $client_ip     = $_SERVER['HTTP_CLIENT_IP'] ?? $forwarded_for ?? $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    // Take first IP in XFF chain
    if ($forwarded_for) {
        $ips = array_map('trim', explode(',', $forwarded_for));
        $client_ip = $ips[0];
    }

    $proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');

    $host   = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'unknown';
    $uri    = $_SERVER['REQUEST_URI'] ?? '/';
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    $server_proto = $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1';

    return [
        'client_ip'      => $client_ip,
        'xff_chain'      => $forwarded_for,
        'method'         => $method,
        'host'           => $host,
        'uri'            => $uri,
        'full_url'       => $proto . '://' . $host . $uri,
        'protocol'       => $server_proto,
        'user_agent'     => $_SERVER['HTTP_USER_AGENT'] ?? 'N/A',
        'accept_encoding'=> $_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'N/A',
        'accept_language'=> $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'N/A',
        'inbound_headers'=> getallheaders() ?: [],
        'cookies'        => $_COOKIE,
        'server_time'    => date('Y-m-d H:i:s T'),
        'server_name'    => gethostname() ?: ($_SERVER['SERVER_NAME'] ?? 'N/A'),
        'php_version'    => PHP_VERSION,
        'tls_cipher'     => $_SERVER['SSL_CIPHER'] ?? $_SERVER['HTTP_X_ARR_SSL'] ?? null,
        'tls_protocol'   => $_SERVER['SSL_PROTOCOL'] ?? null,
    ];
}

// ─── HANDLE PROBE REQUEST (AJAX) ───────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['probe_url'])) {
    header('Content-Type: application/json');
    $url = trim($_POST['probe_url']);
    if (!preg_match('#^https?://#i', $url)) {
        $url = 'https://' . $url;
    }
    $result = probe_url($url);
    if (!isset($result['error'])) {
        $result['security_audit'] = audit_security_headers($result['headers']);
    }
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// ─── INBOUND DATA ──────────────────────────────────────────────────────────────
$inbound      = get_inbound_info();
$inbound_audit = audit_security_headers(array_change_key_case($inbound['inbound_headers'], CASE_LOWER));

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>L7 Tester — Layer 7 Diagnostic Tool</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:       #0a0c10;
    --surface:  #111318;
    --border:   #1e2330;
    --accent:   #00e5ff;
    --accent2:  #7c3aed;
    --pass:     #10b981;
    --warn:     #f59e0b;
    --fail:     #ef4444;
    --text:     #e2e8f0;
    --muted:    #64748b;
    --mono:     'JetBrains Mono', monospace;
    --sans:     'Syne', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    line-height: 1.6;
    min-height: 100vh;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,229,255,0.015) 2px,
      rgba(0,229,255,0.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  header {
    padding: 2rem 2rem 1.5rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: baseline;
    gap: 1rem;
    flex-wrap: wrap;
  }

  header h1 {
    font-family: var(--sans);
    font-size: 1.6rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: #fff;
  }

  header h1 span { color: var(--accent); }

  .tagline {
    color: var(--muted);
    font-size: 11px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  .layout {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0;
    min-height: calc(100vh - 80px);
  }

  @media (max-width: 900px) {
    .layout { grid-template-columns: 1fr; }
  }

  .panel {
    border-right: 1px solid var(--border);
    padding: 1.5rem;
  }

  .panel:last-child { border-right: none; }

  .panel-title {
    font-family: var(--sans);
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .panel-title::before {
    content: '';
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.3; }
  }

  /* ─── PROBE FORM ── */
  .probe-form {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
  }

  .probe-form input {
    flex: 1;
    min-width: 200px;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: var(--mono);
    font-size: 12px;
    padding: 0.6rem 0.8rem;
    outline: none;
    transition: border-color 0.2s;
  }

  .probe-form input:focus { border-color: var(--accent); }
  .probe-form input::placeholder { color: var(--muted); }

  .probe-btn {
    background: var(--accent);
    color: #000;
    border: none;
    font-family: var(--sans);
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 0.6rem 1.2rem;
    cursor: pointer;
    transition: background 0.2s, transform 0.1s;
  }

  .probe-btn:hover   { background: #33eeff; }
  .probe-btn:active  { transform: scale(0.97); }
  .probe-btn:disabled { background: var(--muted); cursor: wait; }

  /* ─── TIMING BAR ── */
  .timing-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 0.4rem;
    margin-bottom: 1.5rem;
  }

  .timing-row {
    display: grid;
    grid-template-columns: 130px 1fr 60px;
    align-items: center;
    gap: 0.5rem;
  }

  .timing-label { color: var(--muted); font-size: 11px; }

  .timing-bar-track {
    background: var(--border);
    height: 6px;
    border-radius: 3px;
    overflow: hidden;
  }

  .timing-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.8s cubic-bezier(0.22, 1, 0.36, 1);
  }

  .timing-val { color: var(--accent); font-size: 11px; text-align: right; }

  /* ─── SECTION ── */
  .section {
    border: 1px solid var(--border);
    margin-bottom: 1rem;
  }

  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.6rem 0.8rem;
    cursor: pointer;
    background: var(--surface);
    user-select: none;
    transition: background 0.15s;
  }

  .section-header:hover { background: #161b25; }

  .section-header h3 {
    font-family: var(--sans);
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text);
  }

  .section-body {
    padding: 0.8rem;
    border-top: 1px solid var(--border);
  }

  .section-body.hidden { display: none; }

  .chevron { color: var(--muted); transition: transform 0.2s; font-size: 10px; }
  .chevron.open { transform: rotate(180deg); }

  /* ─── KV TABLE ── */
  .kv-table { width: 100%; border-collapse: collapse; }

  .kv-table tr { border-bottom: 1px solid var(--border); }
  .kv-table tr:last-child { border-bottom: none; }

  .kv-table td {
    padding: 0.3rem 0.4rem;
    vertical-align: top;
    font-size: 12px;
  }

  .kv-table td:first-child {
    color: var(--muted);
    white-space: nowrap;
    padding-right: 1rem;
    width: 40%;
  }

  .kv-table td:last-child { color: var(--text); word-break: break-all; }

  /* ─── BADGE ── */
  .badge {
    display: inline-block;
    padding: 0.1rem 0.5rem;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    border-radius: 2px;
  }

  .badge-pass  { background: rgba(16,185,129,0.15); color: var(--pass); }
  .badge-warn  { background: rgba(245,158,11,0.15);  color: var(--warn); }
  .badge-fail  { background: rgba(239,68,68,0.15);   color: var(--fail); }
  .badge-info  { background: rgba(0,229,255,0.1);    color: var(--accent); }

  /* ─── SECURITY AUDIT ── */
  .audit-row {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 0.5rem;
    padding: 0.4rem 0;
    border-bottom: 1px solid var(--border);
    align-items: start;
  }

  .audit-row:last-child { border-bottom: none; }

  .audit-name { font-size: 12px; color: var(--text); }
  .audit-desc { font-size: 10px; color: var(--muted); margin-top: 1px; }
  .audit-value { font-size: 10px; color: var(--accent); margin-top: 2px; word-break: break-all; }
  .audit-suggest { font-size: 10px; color: var(--warn); margin-top: 2px; font-style: italic; }

  /* ─── TLS CHAIN ── */
  .chain-cert {
    border-left: 2px solid var(--border);
    padding-left: 0.8rem;
    margin-bottom: 0.6rem;
    font-size: 11px;
  }

  .chain-cert.leaf { border-left-color: var(--accent); }
  .chain-cert-label {
    font-size: 9px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--muted);
    margin-bottom: 0.2rem;
  }

  /* ─── STATUS CODE ── */
  .status-code {
    font-family: var(--sans);
    font-size: 2rem;
    font-weight: 800;
    line-height: 1;
  }

  .status-2xx { color: var(--pass); }
  .status-3xx { color: var(--accent); }
  .status-4xx { color: var(--warn); }
  .status-5xx { color: var(--fail); }

  /* ─── LOADER ── */
  .loader {
    display: none;
    align-items: center;
    gap: 0.5rem;
    color: var(--muted);
    font-size: 11px;
    padding: 1rem 0;
  }

  .loader.active { display: flex; }

  .spinner {
    width: 14px; height: 14px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  /* ─── ERROR ── */
  .error-box {
    background: rgba(239,68,68,0.08);
    border: 1px solid rgba(239,68,68,0.3);
    color: var(--fail);
    padding: 0.8rem;
    font-size: 12px;
    display: none;
  }

  .error-box.active { display: block; }

  /* ─── EXPIRY INDICATOR ── */
  .expiry-good  { color: var(--pass); }
  .expiry-warn  { color: var(--warn); }
  .expiry-crit  { color: var(--fail); }

  /* ─── COPY BTN ── */
  .copy-btn {
    background: none;
    border: 1px solid var(--border);
    color: var(--muted);
    font-family: var(--mono);
    font-size: 10px;
    padding: 0.2rem 0.5rem;
    cursor: pointer;
    transition: all 0.15s;
  }

  .copy-btn:hover { border-color: var(--accent); color: var(--accent); }

  footer {
    text-align: center;
    padding: 1.5rem;
    color: var(--muted);
    font-size: 10px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    border-top: 1px solid var(--border);
  }
</style>
</head>
<body>

<header>
  <h1>L7<span>TESTER</span></h1>
  <span class="tagline">Layer 7 Diagnostic Tool &mdash; PHP <?= PHP_VERSION ?></span>
</header>

<div class="layout">

  <!-- ══════════════════════════════════════════════
       LEFT PANEL — Outbound Probe
  ══════════════════════════════════════════════ -->
  <div class="panel">
    <div class="panel-title">Outbound URL Probe</div>

    <div class="probe-form">
      <input type="text" id="probe-input" placeholder="https://example.com" autocomplete="off" spellcheck="false">
      <button class="probe-btn" id="probe-btn" onclick="runProbe()">▶ Probe</button>
    </div>

    <div class="loader" id="loader"><div class="spinner"></div> Running L7 diagnostic…</div>
    <div class="error-box" id="error-box"></div>

    <div id="probe-results" style="display:none">

      <!-- Status + summary -->
      <div style="display:flex; align-items:baseline; gap:1rem; margin-bottom:1.5rem; flex-wrap:wrap;">
        <div class="status-code" id="r-status"></div>
        <div>
          <div id="r-status-line" style="font-size:12px; color:var(--muted)"></div>
          <div id="r-url" style="font-size:11px; color:var(--accent); word-break:break-all; margin-top:2px;"></div>
        </div>
        <div style="margin-left:auto; display:flex; gap:0.5rem; flex-wrap:wrap;" id="r-badges"></div>
      </div>

      <!-- Timing waterfall -->
      <div class="section">
        <div class="section-header" onclick="toggle(this)">
          <h3>Timing Waterfall</h3><span class="chevron open">▲</span>
        </div>
        <div class="section-body" id="timing-section">
          <div class="timing-grid" id="timing-grid"></div>
        </div>
      </div>

      <!-- TLS Details -->
      <div class="section" id="tls-section">
        <div class="section-header" onclick="toggle(this)">
          <h3>TLS / Certificate</h3><span class="chevron open">▲</span>
        </div>
        <div class="section-body" id="tls-body"></div>
      </div>

      <!-- Security Header Audit -->
      <div class="section">
        <div class="section-header" onclick="toggle(this)">
          <h3>Security Header Audit</h3><span class="chevron open">▲</span>
        </div>
        <div class="section-body" id="audit-body"></div>
      </div>

      <!-- Response Headers -->
      <div class="section">
        <div class="section-header" onclick="toggle(this)">
          <h3>Response Headers</h3><span class="chevron">▲</span>
        </div>
        <div class="section-body hidden" id="resp-headers-body"></div>
      </div>

    </div><!-- /probe-results -->
  </div>

  <!-- ══════════════════════════════════════════════
       RIGHT PANEL — Inbound Request
  ══════════════════════════════════════════════ -->
  <div class="panel">
    <div class="panel-title">Inbound Request (Your Session)</div>

    <!-- Client summary -->
    <div style="display:flex; gap:1.5rem; flex-wrap:wrap; margin-bottom:1.5rem;">
      <div>
        <div style="font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.1em;">Your IP</div>
        <div style="font-size:1.1rem; font-family:var(--sans); font-weight:700; color:var(--accent);"><?= htmlspecialchars($inbound['client_ip']) ?></div>
      </div>
      <div>
        <div style="font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.1em;">Protocol</div>
        <div style="font-size:1.1rem; font-family:var(--sans); font-weight:700; color:var(--text);"><?= htmlspecialchars($inbound['protocol']) ?></div>
      </div>
      <div>
        <div style="font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.1em;">Server Time</div>
        <div style="font-size:1.1rem; font-family:var(--sans); font-weight:700; color:var(--text);"><?= htmlspecialchars($inbound['server_time']) ?></div>
      </div>
    </div>

    <!-- Request Details -->
    <div class="section">
      <div class="section-header" onclick="toggle(this)">
        <h3>Request Details</h3><span class="chevron open">▲</span>
      </div>
      <div class="section-body">
        <table class="kv-table">
          <tr><td>Method</td><td><?= htmlspecialchars($inbound['method']) ?></td></tr>
          <tr><td>Host</td><td><?= htmlspecialchars($inbound['host']) ?></td></tr>
          <tr><td>URI</td><td><?= htmlspecialchars($inbound['uri']) ?></td></tr>
          <tr><td>Full URL</td><td><?= htmlspecialchars($inbound['full_url']) ?></td></tr>
          <tr><td>User-Agent</td><td><?= htmlspecialchars($inbound['user_agent']) ?></td></tr>
          <tr><td>Accept-Encoding</td><td><?= htmlspecialchars($inbound['accept_encoding']) ?></td></tr>
          <tr><td>Accept-Language</td><td><?= htmlspecialchars($inbound['accept_language']) ?></td></tr>
          <tr><td>Server Hostname</td><td><?= htmlspecialchars($inbound['server_name']) ?></td></tr>
          <?php if ($inbound['xff_chain']): ?>
          <tr><td>X-Forwarded-For</td><td><?= htmlspecialchars($inbound['xff_chain']) ?></td></tr>
          <?php endif; ?>
          <?php if ($inbound['tls_protocol']): ?>
          <tr><td>TLS Protocol</td><td><?= htmlspecialchars($inbound['tls_protocol']) ?></td></tr>
          <?php endif; ?>
          <?php if ($inbound['tls_cipher']): ?>
          <tr><td>TLS Cipher</td><td><?= htmlspecialchars($inbound['tls_cipher']) ?></td></tr>
          <?php endif; ?>
        </table>
      </div>
    </div>

    <!-- Security Header Audit (inbound) -->
    <div class="section">
      <div class="section-header" onclick="toggle(this)">
        <h3>Security Header Audit (This Server)</h3><span class="chevron open">▲</span>
      </div>
      <div class="section-body">
        <?php foreach ($inbound_audit as $a): ?>
        <div class="audit-row">
          <div>
            <div class="audit-name"><?= htmlspecialchars($a['name']) ?></div>
            <div class="audit-desc"><?= htmlspecialchars($a['desc']) ?></div>
            <?php if ($a['value']): ?>
            <div class="audit-value"><?= htmlspecialchars($a['value']) ?></div>
            <?php endif; ?>
            <?php if ($a['suggest']): ?>
            <div class="audit-suggest">Suggested: <?= htmlspecialchars($a['suggest']) ?></div>
            <?php endif; ?>
          </div>
          <span class="badge <?= $a['pass'] ? 'badge-pass' : 'badge-fail' ?>"><?= $a['pass'] ? 'PASS' : 'MISSING' ?></span>
        </div>
        <?php endforeach; ?>
      </div>
    </div>

    <!-- All Inbound Headers -->
    <div class="section">
      <div class="section-header" onclick="toggle(this)">
        <h3>All Inbound Headers</h3><span class="chevron">▲</span>
      </div>
      <div class="section-body hidden">
        <button class="copy-btn" onclick="copyHeaders()">Copy</button>
        <table class="kv-table" style="margin-top:.5rem;" id="inbound-headers-table">
          <?php foreach ($inbound['inbound_headers'] as $k => $v): ?>
          <tr>
            <td><?= htmlspecialchars($k) ?></td>
            <td><?= htmlspecialchars($v) ?></td>
          </tr>
          <?php endforeach; ?>
        </table>
      </div>
    </div>

    <!-- Cookies -->
    <?php if (!empty($inbound['cookies'])): ?>
    <div class="section">
      <div class="section-header" onclick="toggle(this)">
        <h3>Cookies (<?= count($inbound['cookies']) ?>)</h3><span class="chevron">▲</span>
      </div>
      <div class="section-body hidden">
        <table class="kv-table">
          <?php foreach ($inbound['cookies'] as $k => $v): ?>
          <tr>
            <td><?= htmlspecialchars($k) ?></td>
            <td><?= htmlspecialchars($v) ?></td>
          </tr>
          <?php endforeach; ?>
        </table>
      </div>
    </div>
    <?php endif; ?>

  </div><!-- /right panel -->
</div><!-- /layout -->

<footer>l7tester.com &mdash; Layer 7 Diagnostic Tool &mdash; PHP <?= PHP_VERSION ?> on Azure</footer>

<script>
function toggle(header) {
  const body    = header.nextElementSibling;
  const chevron = header.querySelector('.chevron');
  body.classList.toggle('hidden');
  chevron.classList.toggle('open');
}

function statusClass(code) {
  if (code >= 500) return 'status-5xx';
  if (code >= 400) return 'status-4xx';
  if (code >= 300) return 'status-3xx';
  return 'status-2xx';
}

function msColor(ms) {
  if (ms === null) return 'var(--muted)';
  if (ms < 100)   return 'var(--pass)';
  if (ms < 500)   return 'var(--warn)';
  return 'var(--fail)';
}

function timingBarColor(label) {
  const map = {
    'DNS Resolve':    '#f59e0b',
    'TCP Connect':    '#3b82f6',
    'TLS Handshake':  '#8b5cf6',
    'TTFB':           '#10b981',
    'Total':          '#00e5ff',
  };
  return map[label] || '#64748b';
}

function renderTimings(timings) {
  const rows = [
    { label: 'DNS Resolve',   val: timings.dns_resolve_ms },
    { label: 'TCP Connect',   val: timings.tcp_connect_ms },
    { label: 'TLS Handshake', val: timings.tls_handshake_ms },
    { label: 'TTFB',          val: timings.ttfb_ms },
    { label: 'Total',         val: timings.total_ms },
  ];
  const max = Math.max(...rows.map(r => r.val ?? 0), 1);
  const grid = document.getElementById('timing-grid');
  grid.innerHTML = '';
  rows.forEach(row => {
    const pct  = row.val !== null ? Math.max(2, (row.val / max) * 100) : 0;
    const color = timingBarColor(row.label);
    const valStr = row.val !== null ? row.val + ' ms' : 'N/A';
    grid.innerHTML += `
      <div class="timing-row">
        <span class="timing-label">${row.label}</span>
        <div class="timing-bar-track">
          <div class="timing-bar-fill" style="width:0%; background:${color}" data-target="${pct}"></div>
        </div>
        <span class="timing-val" style="color:${msColor(row.val)}">${valStr}</span>
      </div>`;
  });
  // Animate bars after a tick
  setTimeout(() => {
    grid.querySelectorAll('.timing-bar-fill').forEach(bar => {
      bar.style.width = bar.dataset.target + '%';
    });
  }, 50);
}

function renderTLS(tls) {
  const sec = document.getElementById('tls-section');
  const body = document.getElementById('tls-body');
  if (!tls || Object.keys(tls).length === 0) {
    sec.style.display = 'none';
    return;
  }
  sec.style.display = '';

  const days = tls.days_remaining;
  let expiryClass = 'expiry-good';
  let expiryNote  = days + ' days remaining';
  if (days <= 14)       { expiryClass = 'expiry-crit'; expiryNote += ' ⚠ CRITICAL'; }
  else if (days <= 30)  { expiryClass = 'expiry-warn'; expiryNote += ' ⚠ Expiring soon'; }

  let chainHtml = '';
  (tls.chain || []).forEach((cert, i) => {
    const cls = i === 0 ? 'leaf' : '';
    const label = i === 0 ? 'Leaf Certificate' : (i === tls.chain_depth - 1 ? 'Root CA' : `Intermediate CA ${i}`);
    chainHtml += `
      <div class="chain-cert ${cls}">
        <div class="chain-cert-label">${label}</div>
        <div style="color:var(--text)">${cert.subject || 'N/A'}</div>
        <div style="color:var(--muted); font-size:10px;">Issuer: ${cert.issuer || 'N/A'}</div>
        <div style="font-size:10px; color:var(--muted);">Expires: ${cert.expire || 'N/A'}</div>
      </div>`;
  });

  body.innerHTML = `
    <table class="kv-table" style="margin-bottom:1rem">
      <tr><td>Subject</td><td>${tls.subject ?? 'N/A'}</td></tr>
      <tr><td>Issuer</td><td>${tls.issuer ?? 'N/A'}</td></tr>
      <tr><td>Valid From</td><td>${tls.start ?? 'N/A'}</td></tr>
      <tr><td>Expires</td><td><span class="${expiryClass}">${tls.expire ?? 'N/A'} &mdash; ${expiryNote}</span></td></tr>
      <tr><td>Chain Depth</td><td>${tls.chain_depth ?? 'N/A'} cert(s)</td></tr>
    </table>
    <div style="font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.1em; margin-bottom:.5rem;">Certificate Chain</div>
    ${chainHtml}`;
}

function renderAudit(audit) {
  const body = document.getElementById('audit-body');
  body.innerHTML = '';
  audit.forEach(a => {
    const badge = a.pass
      ? '<span class="badge badge-pass">PASS</span>'
      : '<span class="badge badge-fail">MISSING</span>';
    const val     = a.value   ? `<div class="audit-value">${escHtml(a.value)}</div>` : '';
    const suggest = a.suggest ? `<div class="audit-suggest">Suggested: ${escHtml(a.suggest)}</div>` : '';
    body.innerHTML += `
      <div class="audit-row">
        <div>
          <div class="audit-name">${escHtml(a.name)}</div>
          <div class="audit-desc">${escHtml(a.desc)}</div>
          ${val}${suggest}
        </div>
        ${badge}
      </div>`;
  });
}

function renderHeaders(headers) {
  const body = document.getElementById('resp-headers-body');
  let html = '<table class="kv-table">';
  Object.entries(headers).forEach(([k, v]) => {
    html += `<tr><td>${escHtml(k)}</td><td>${escHtml(v)}</td></tr>`;
  });
  html += '</table>';
  body.innerHTML = html;
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function runProbe() {
  const input = document.getElementById('probe-input').value.trim();
  if (!input) return;

  const btn     = document.getElementById('probe-btn');
  const loader  = document.getElementById('loader');
  const errBox  = document.getElementById('error-box');
  const results = document.getElementById('probe-results');

  btn.disabled = true;
  loader.classList.add('active');
  errBox.classList.remove('active');
  results.style.display = 'none';

  try {
    const fd = new FormData();
    fd.append('probe_url', input);
    const resp = await fetch(window.location.href, { method: 'POST', body: fd });
    const data = await resp.json();

    if (data.error) {
      errBox.textContent = '✕ ' + data.error;
      errBox.classList.add('active');
    } else {
      // Status
      const sc = document.getElementById('r-status');
      sc.textContent = data.status_code;
      sc.className   = 'status-code ' + statusClass(data.status_code);
      document.getElementById('r-status-line').textContent = data.status_line;
      document.getElementById('r-url').textContent = data.url;

      // Badges
      const badges = document.getElementById('r-badges');
      badges.innerHTML = '';
      if (data.http_version) badges.innerHTML += `<span class="badge badge-info">${escHtml(data.http_version)}</span>`;
      if (data.ip)           badges.innerHTML += `<span class="badge badge-info">${escHtml(data.ip)}:${data.port}</span>`;
      if (data.redirect_count > 0) badges.innerHTML += `<span class="badge badge-warn">${data.redirect_count} redirect(s)</span>`;

      renderTimings(data.timings);
      renderTLS(data.tls);
      renderAudit(data.security_audit || []);
      renderHeaders(data.headers || {});

      results.style.display = 'block';
    }
  } catch (e) {
    errBox.textContent = '✕ Request failed: ' + e.message;
    errBox.classList.add('active');
  } finally {
    btn.disabled = false;
    loader.classList.remove('active');
  }
}

// Allow Enter key to trigger probe
document.getElementById('probe-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') runProbe();
});

function copyHeaders() {
  const rows = document.querySelectorAll('#inbound-headers-table tr');
  const text = Array.from(rows).map(r => {
    const cells = r.querySelectorAll('td');
    return cells[0]?.textContent + ': ' + cells[1]?.textContent;
  }).join('\n');
  navigator.clipboard.writeText(text).catch(() => {});
}
</script>
</body>
</html>
