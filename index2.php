<?php
// l7tester-like single-file tool: Reflector + URL probe + DNS resolver

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function is_private_ip($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return true;
    // blocks private + reserved ranges
    return (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false);
}

function resolve_all_ips($host) {
    $ips = [];
    $a = @dns_get_record($host, DNS_A);
    if (is_array($a)) foreach ($a as $r) if (!empty($r['ip'])) $ips[] = $r['ip'];
    $aaaa = @dns_get_record($host, DNS_AAAA);
    if (is_array($aaaa)) foreach ($aaaa as $r) if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
    $ips = array_values(array_unique($ips));
    return $ips;
}

function parse_tls_from_verbose($verboseText) {
    $out = [
        'tls_version' => null,
        'cipher'      => null,
        'alpn'        => null,
        'raw'         => $verboseText,
    ];

    // Example: "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384"
    if (preg_match('/SSL connection using\s+([^\s]+)\s+\/\s+([^\r\n]+)/i', $verboseText, $m)) {
        $out['tls_version'] = trim($m[1]);
        $out['cipher']      = trim($m[2]);
    }

    if (preg_match('/ALPN,\s*server accepted to use\s*([^\r\n]+)/i', $verboseText, $m)) {
        $out['alpn'] = trim($m[1]);
    } elseif (preg_match('/ALPN,\s*server did not agree to a protocol/i', $verboseText)) {
        $out['alpn'] = '(no agreement)';
    }

    return $out;
}

function timing_breakdown_from_curlinfo(array $info) {
    // curl_getinfo timings are cumulative from the start. 【2-9f89bf】
    $nl  = (float)($info['namelookup_time'] ?? 0);
    $ct  = (float)($info['connect_time'] ?? 0);
    $ac  = (float)($info['appconnect_time'] ?? 0);     // TLS handshake completion (if HTTPS) 【1-22cf0a】
    $pt  = (float)($info['pretransfer_time'] ?? 0);
    $st  = (float)($info['starttransfer_time'] ?? 0);  // “TTFB total” 【2-9f89bf】
    $tt  = (float)($info['total_time'] ?? 0);

    $dns_ms  = max(0, ($nl) * 1000);
    $tcp_ms  = max(0, ($ct - $nl) * 1000);

    // pretransfer_time is “ready to transfer”; for HTTPS it's typically after TLS.
    // Use pretransfer_time to compute "wait after handshake/ready" more robustly.
    $tls_ms  = 0;
    if ($ac > 0) {
        $tls_ms = max(0, ($ac - $ct) * 1000);
    }

    $ttfb_total_ms = max(0, $st * 1000);
    $ttfb_after_ready_ms = max(0, ($st - $pt) * 1000); // recommended “wait after ready” metric 【2-9f89bf】
    $transfer_ms = max(0, ($tt - $st) * 1000);
    $total_ms = max(0, $tt * 1000);

    return [
        'dns_ms' => round($dns_ms, 2),
        'tcp_ms' => round($tcp_ms, 2),
        'tls_ms' => round($tls_ms, 2),
        'ttfb_total_ms' => round($ttfb_total_ms, 2),
        'ttfb_after_ready_ms' => round($ttfb_after_ready_ms, 2),
        'transfer_ms' => round($transfer_ms, 2),
        'total_ms' => round($total_ms, 2),
        'raw_seconds' => [
            'namelookup_time' => $nl,
            'connect_time' => $ct,
            'appconnect_time' => $ac,
            'pretransfer_time' => $pt,
            'starttransfer_time' => $st,
            'total_time' => $tt,
        ],
    ];
}

function probe_url($url, $opts = []) {
    $timeoutSec = (int)($opts['timeout'] ?? 10);
    $follow = !empty($opts['follow']);
    $method = strtoupper($opts['method'] ?? 'HEAD');

    $u = parse_url($url);
    if (!$u || empty($u['scheme']) || empty($u['host'])) throw new Exception("Invalid URL");
    $scheme = strtolower($u['scheme']);
    if (!in_array($scheme, ['http','https'], true)) throw new Exception("Only http/https URLs are allowed.");

    // SSRF guard: resolve host IPs and block private/reserved
    $ips = resolve_all_ips($u['host']);
    if (!$ips) throw new Exception("DNS resolution failed for host: ".$u['host']);
    foreach ($ips as $ip) {
        if (is_private_ip($ip)) throw new Exception("Blocked destination (private/reserved IP): $ip");
    }

    $respHeaders = [];
    $statusLines = [];

    $ch = curl_init($url);

    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($curl, $headerLine) use (&$respHeaders, &$statusLines) {
        $len = strlen($headerLine);
        $line = trim($headerLine);
        if ($line === '') return $len;
        if (stripos($line, 'HTTP/') === 0) { $statusLines[] = $line; return $len; }
        $parts = explode(':', $line, 2);
        if (count($parts) === 2) {
            $k = strtolower(trim($parts[0]));
            $v = trim($parts[1]);
            if (!isset($respHeaders[$k])) $respHeaders[$k] = [];
            $respHeaders[$k][] = $v;
        }
        return $len;
    });

    // discard body
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, function($curl, $data) { return strlen($data); });

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeoutSec);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeoutSec);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $follow ? 1 : 0);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 8);
    curl_setopt($ch, CURLOPT_USERAGENT, "l7tester/1.0");

    // HEAD by default so we measure quickly
    if ($method === 'HEAD') {
        curl_setopt($ch, CURLOPT_NOBODY, 1);
    } else {
        curl_setopt($ch, CURLOPT_NOBODY, 0);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    }

    // Collect certificate chain info (if supported) 【8-c8d52a】【1-22cf0a】
    curl_setopt($ch, CURLOPT_CERTINFO, 1);

    // Capture verbose TLS/ALPN info (goes to stderr by default) 【9-e2ffae】
    $stderr = fopen('php://temp', 'w+');
    curl_setopt($ch, CURLOPT_VERBOSE, 1);
    curl_setopt($ch, CURLOPT_STDERR, $stderr);

    $ok = curl_exec($ch);

    rewind($stderr);
    $verboseText = stream_get_contents($stderr);
    fclose($stderr);

    $errNo  = curl_errno($ch);
    $errStr = curl_error($ch);
    $info = curl_getinfo($ch); // includes timing fields like starttransfer_time, total_time etc. 【1-22cf0a】
    curl_close($ch);

    if ($ok === false || $errNo) throw new Exception("cURL error ($errNo): $errStr");

    $tlsVerbose = parse_tls_from_verbose($verboseText);
    $timings = timing_breakdown_from_curlinfo($info);

    // parse certinfo if present
    $certChain = [];
    if (!empty($info['certinfo']) && is_array($info['certinfo'])) {
        foreach ($info['certinfo'] as $idx => $certEntry) {
            $parsed = null;
            if (isset($certEntry['Cert'])) {
                $parsed = @openssl_x509_parse($certEntry['Cert']);
            }
            $certChain[] = ['index' => $idx, 'raw' => $certEntry, 'parsed' => $parsed];
        }
    }

    return [
        'request' => [
            'url' => $url,
            'host' => $u['host'],
            'resolved_ips' => $ips,
            'method' => $method,
            'follow_redirects' => $follow,
        ],
        'http' => [
            'status_lines' => $statusLines,
            'headers' => $respHeaders,
            'http_code' => $info['http_code'] ?? null,
            'effective_url' => $info['url'] ?? null,
            'primary_ip' => $info['primary_ip'] ?? null,
            'primary_port' => $info['primary_port'] ?? null,
            'redirect_count' => $info['redirect_count'] ?? null,
            'redirect_time' => $info['redirect_time'] ?? null,
        ],
        'timings' => $timings,
        'tls' => [
            'ssl_verify_result' => $info['ssl_verify_result'] ?? null,
            'negotiated' => $tlsVerbose,
            'cert_chain' => $certChain,
        ],
        'curl_info' => $info,
    ];
}

// ---- DNS resolver (system + DoH) ----

function dns_query_system($name, $type) {
    // dns_get_record supports many DNS_* types. 【4-5e71a2】
    $map = [
        'A' => DNS_A,
        'AAAA' => DNS_AAAA,
        'CNAME' => DNS_CNAME,
        'NS' => DNS_NS,
        'MX' => DNS_MX,
        'TXT' => DNS_TXT,
        'SOA' => DNS_SOA,
        'SRV' => DNS_SRV,
        'CAA' => defined('DNS_CAA') ? DNS_CAA : DNS_ANY,
        'ANY' => DNS_ANY,
        'ALL' => DNS_ALL, // more reliable than ANY on some platforms 【4-5e71a2】
    ];
    $flag = $map[$type] ?? DNS_ANY;
    $auth = null; $addtl = null;
    $res = @dns_get_record($name, $flag, $auth, $addtl);
    if ($res === false) return ['error' => 'dns_get_record failed', 'records' => []];
    return ['records' => $res, 'auth' => $auth, 'additional' => $addtl];
}

function http_get_json($url, $headers = []) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $body = curl_exec($ch);
    $errNo = curl_errno($ch);
    $errStr = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($body === false || $errNo) {
        return ['error' => "cURL error ($errNo): $errStr", 'http_code' => $code, 'json' => null];
    }
    $json = json_decode($body, true);
    if (!is_array($json)) return ['error' => 'Invalid JSON', 'http_code' => $code, 'json' => null, 'raw' => $body];
    return ['error' => null, 'http_code' => $code, 'json' => $json];
}

function dns_query_doh_cloudflare($name, $type) {
    // Cloudflare DoH JSON format: GET /dns-query?name=...&type=... with Accept: application/dns-json 【5-544d7c】
    $q = "https://cloudflare-dns.com/dns-query?name=" . rawurlencode($name) . "&type=" . rawurlencode($type);
    return http_get_json($q, ["accept: application/dns-json"]);
}

function dns_query_doh_google($name, $type) {
    // Google JSON API: https://dns.google/resolve?name=...&type=... 【6-b46171】【7-37378c】
    $q = "https://dns.google/resolve?name=" . rawurlencode($name) . "&type=" . rawurlencode($type);
    return http_get_json($q, ["accept: application/json"]);
}

// ---- UI ----
$mode = $_GET['mode'] ?? 'home';

?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>l7tester - Headers / Probe / DNS</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 18px; }
    .box { border: 1px solid #ddd; padding: 12px; margin: 12px 0; border-radius: 8px; }
    pre { background: #f6f8fa; padding: 12px; overflow:auto; }
    input[type=text] { width: 520px; max-width: 95%; padding: 8px; }
    select, input[type=number] { padding: 6px; }
    button { padding: 8px 12px; }
    .pill { display:inline-block; padding:4px 10px; background:#eef; border-radius:999px; margin: 2px 6px 2px 0; }
    .nav a { margin-right: 12px; }
  </style>
</head>
<body>

<h1>l7tester.com toolbox</h1>
<div class="nav box">
  <a href="?mode=home">Incoming Reflector</a>
  <a href="?mode=probe">URL Probe (timings + TLS)</a>
  <a href="?mode=dns">DNS Resolver</a>
</div>

<?php if ($mode === 'home'): ?>
  <div class="box">
    <h2>Incoming request headers (what your client sent to this site)</h2>
    <pre><?php print_r(getallheaders()); ?></pre>

    <h3>Request info</h3>
    <div class="pill">Method: <?php echo h($_SERVER['REQUEST_METHOD'] ?? ''); ?></div>
    <div class="pill">URI: <?php echo h($_SERVER['REQUEST_URI'] ?? ''); ?></div>
    <div class="pill">Client IP: <?php echo h($_SERVER['REMOTE_ADDR'] ?? ''); ?></div>
    <div class="pill">User-Agent: <?php echo h($_SERVER['HTTP_USER_AGENT'] ?? ''); ?></div>

    <h3>Cookies</h3>
    <pre><?php print_r($_COOKIE); ?></pre>
  </div>
<?php endif; ?>

<?php if ($mode === 'probe'):
  $target = $_GET['target'] ?? 'https://www.google.com';
  $follow = !empty($_GET['follow']);
  $method = $_GET['method'] ?? 'HEAD';
  $timeout = (int)($_GET['timeout'] ?? 10);
?>
  <div class="box">
    <h2>URL Probe (timings + TLS)</h2>
    <form method="get">
      <input type="hidden" name="mode" value="probe">
      <div>
        <label>Target URL:</label><br>
        <input type="text" name="target" value="<?php echo h($target); ?>">
      </div>
      <div style="margin-top:10px;">
        <label>Method:</label>
        <select name="method">
          <?php foreach (['HEAD','GET'] as $m): ?>
            <option value="<?php echo h($m); ?>" <?php echo ($method===$m?'selected':''); ?>><?php echo h($m); ?></option>
          <?php endforeach; ?>
        </select>

        <label style="margin-left:12px;">Timeout (sec):</label>
        <input type="number" name="timeout" value="<?php echo h($timeout); ?>" min="1" max="60">

        <label style="margin-left:12px;">
          <input type="checkbox" name="follow" value="1" <?php echo ($follow?'checked':''); ?>>
          Follow redirects
        </label>

        <button type="submit" style="margin-left:12px;">Probe</button>
      </div>
      <p style="color:#666;">
        Tip: If you see huge TTFB on google.com, try disabling redirects (or use https://www.google.com directly). Redirects are included when follow is enabled. 【2-9f89bf】【1-22cf0a】
      </p>
    </form>
  </div>

  <?php
  try {
      $report = probe_url($target, ['follow'=>$follow, 'method'=>$method, 'timeout'=>$timeout]);
  ?>
  <div class="box">
    <h3>Summary</h3>
    <div class="pill">HTTP: <?php echo h($report['http']['http_code']); ?></div>
    <div class="pill">Effective URL: <?php echo h($report['http']['effective_url']); ?></div>
    <div class="pill">Primary IP: <?php echo h($report['http']['primary_ip']); ?></div>
    <div class="pill">Redirects: <?php echo h($report['http']['redirect_count']); ?></div>
    <div class="pill">Redirect time: <?php echo h($report['http']['redirect_time']); ?>s</div>

    <h3>Timing breakdown (ms)</h3>
    <?php foreach (['dns_ms','tcp_ms','tls_ms','ttfb_total_ms','ttfb_after_ready_ms','transfer_ms','total_ms'] as $k): ?>
      <div class="pill"><?php echo h($k); ?>: <?php echo h($report['timings'][$k]); ?></div>
    <?php endforeach; ?>
    <p style="color:#666;">
      Raw cURL timings are cumulative; deltas are computed accordingly. 【2-9f89bf】【1-22cf0a】
    </p>

    <h3>TLS negotiated (best-effort from cURL verbose)</h3>
    <pre><?php print_r($report['tls']['negotiated']); ?></pre>

    <h3>Response headers</h3>
    <pre><?php print_r($report['http']['status_lines']); print_r($report['http']['headers']); ?></pre>

    <h3>cURL info (debug)</h3>
    <pre><?php print_r($report['curl_info']); ?></pre>
  </div>
  <?php
  } catch (Exception $e) {
      echo '<div class="box"><h3 style="color:#b00;">Probe failed</h3><pre>'.h($e->getMessage()).'</pre></div>';
  }
  ?>
<?php endif; ?>

<?php if ($mode === 'dns'):
  $name = $_GET['name'] ?? 'google.com';
  $type = strtoupper($_GET['type'] ?? 'A');
  $resolver = $_GET['resolver'] ?? 'system';
  $types = ['A','AAAA','CNAME','NS','MX','TXT','SOA','SRV','CAA','ANY','ALL'];
?>
  <div class="box">
    <h2>DNS Resolver</h2>
    <form method="get">
      <input type="hidden" name="mode" value="dns">
      <div>
        <label>Name:</label><br>
        <input type="text" name="name" value="<?php echo h($name); ?>">
      </div>

      <div style="margin-top:10px;">
        <label>Type:</label>
        <select name="type">
          <?php foreach ($types as $t): ?>
            <option value="<?php echo h($t); ?>" <?php echo ($type===$t?'selected':''); ?>><?php echo h($t); ?></option>
          <?php endforeach; ?>
        </select>

        <label style="margin-left:12px;">Resolver:</label>
        <select name="resolver">
          <option value="system" <?php echo ($resolver==='system'?'selected':''); ?>>System (dns_get_record)</option>
          <option value="cloudflare" <?php echo ($resolver==='cloudflare'?'selected':''); ?>>Cloudflare DoH</option>
          <option value="google" <?php echo ($resolver==='google'?'selected':''); ?>>Google DoH</option>
        </select>

        <button type="submit" style="margin-left:12px;">Resolve</button>
      </div>

      <p style="color:#666;">
        System resolver uses <code>dns_get_record()</code> (record types via DNS_* constants). 【4-5e71a2】
        Cloudflare/Google options use DNS-over-HTTPS JSON APIs. 【5-544d7c】【6-b46171】
      </p>
    </form>
  </div>

  <div class="box">
    <h3>Results</h3>
    <?php
      if ($resolver === 'system') {
          $res = dns_query_system($name, $type);
          echo '<pre>'; print_r($res); echo '</pre>';
      } elseif ($resolver === 'cloudflare') {
          $res = dns_query_doh_cloudflare($name, $type);
          echo '<pre>'; print_r($res); echo '</pre>';
      } else {
          $res = dns_query_doh_google($name, $type);
          echo '<pre>'; print_r($res); echo '</pre>';
      }
    ?>
  </div>
<?php endif; ?>

</body>
</html>
