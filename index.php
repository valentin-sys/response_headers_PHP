<?php
// index.php — reflector + outbound probe (timings + TLS/cert inspection)

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function is_private_ip($ip) {
    // Basic SSRF guard (not exhaustive). Blocks RFC1918, loopback, link-local, etc.
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return true;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return true;
    return false;
}

function parse_tls_from_verbose($verboseText) {
    $out = [
        'tls_version' => null,
        'cipher'      => null,
        'alpn'        => null,
        'raw'         => $verboseText,
    ];

    // Typical line: "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384"
    if (preg_match('/SSL connection using\s+([^\s]+)\s+\/\s+([^\r\n]+)/i', $verboseText, $m)) {
        $out['tls_version'] = trim($m[1]);
        $out['cipher']      = trim($m[2]);
    }

    // ALPN lines vary by backend; common ones:
    // "* ALPN, server accepted to use h2"
    if (preg_match('/ALPN,\s*server accepted to use\s*([^\r\n]+)/i', $verboseText, $m)) {
        $out['alpn'] = trim($m[1]);
    } elseif (preg_match('/ALPN,\s*server did not agree to a protocol/i', $verboseText)) {
        $out['alpn'] = '(no agreement)';
    }

    return $out;
}

function probe_url($url, $timeoutSec = 10, $followRedirects = true) {
    $u = parse_url($url);
    if (!$u || empty($u['scheme']) || empty($u['host'])) {
        throw new Exception("Invalid URL.");
    }
    if (!in_array(strtolower($u['scheme']), ['http', 'https'], true)) {
        throw new Exception("Only http/https URLs are allowed.");
    }

    // Resolve host and block private/reserved destinations (basic SSRF mitigation)
    $host = $u['host'];
    $ip = gethostbyname($host);
    if ($ip === $host) {
        throw new Exception("DNS resolution failed for host: $host");
    }
    if (is_private_ip($ip)) {
        throw new Exception("Blocked destination (private/reserved IP): $ip");
    }

    $respHeaders = [];
    $statusLine = null;

    $ch = curl_init($url);

    // Capture response headers reliably
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($curl, $headerLine) use (&$respHeaders, &$statusLine) {
        $len = strlen($headerLine);
        $line = trim($headerLine);

        if ($line === '') return $len;

        // Status line(s) appear as headers too
        if (stripos($line, 'HTTP/') === 0) {
            $statusLine = $line;
            return $len;
        }

        $parts = explode(':', $line, 2);
        if (count($parts) === 2) {
            $k = strtolower(trim($parts[0]));
            $v = trim($parts[1]);
            if (!isset($respHeaders[$k])) $respHeaders[$k] = [];
            $respHeaders[$k][] = $v;
        }
        return $len;
    });

    // Don’t store body in memory; discard it
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, function($curl, $data) {
        return strlen($data);
    });

    // Core options
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeoutSec);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeoutSec);
    curl_setopt($ch, CURLOPT_USERAGENT, "l7tester/1.0");

    // Follow redirects (optional)
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $followRedirects ? 1 : 0);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 5);

    // Ask for cert chain information (TLS)
    curl_setopt($ch, CURLOPT_CERTINFO, 1); // enables CURLINFO_CERTINFO/certinfo 【2-f92b92】【1-11de95】

    // Capture verbose output for negotiated TLS/cipher/ALPN
    $stderr = fopen('php://temp', 'w+');
    curl_setopt($ch, CURLOPT_VERBOSE, 1);   // verbose goes to stderr 【4-5abba8】
    curl_setopt($ch, CURLOPT_STDERR, $stderr);

    // Execute
    $ok = curl_exec($ch);

    // Gather outputs
    rewind($stderr);
    $verboseText = stream_get_contents($stderr);
    fclose($stderr);

    $errNo  = curl_errno($ch);
    $errStr = curl_error($ch);

    $info = curl_getinfo($ch); // includes timings + primary_ip + certinfo, etc. 【1-11de95】
    curl_close($ch);

    if ($ok === false || $errNo) {
        throw new Exception("cURL error ($errNo): $errStr");
    }

    // Timing breakdown:
    // curl_getinfo timings are cumulative from request start, so derive per-phase deltas. 【3-ce94f1】
    $t = [
        'dns_s'   => $info['namelookup_time'] ?? null,
        'conn_s'  => $info['connect_time'] ?? null,
        'tls_s'   => $info['appconnect_time'] ?? null,     // TLS handshake completion time 【1-11de95】
        'ttfb_s'  => $info['starttransfer_time'] ?? null,
        'total_s' => $info['total_time'] ?? null,
    ];

    $breakdown = null;
    if ($t['dns_s'] !== null && $t['conn_s'] !== null && $t['ttfb_s'] !== null && $t['total_s'] !== null) {
        $dns = $t['dns_s'];
        $tcp = max(0.0, $t['conn_s'] - $t['dns_s']);
        $tls = ($t['tls_s'] !== null && $t['tls_s'] > 0) ? max(0.0, $t['tls_s'] - $t['conn_s']) : 0.0;
        $ttfb = ($t['tls_s'] !== null && $t['tls_s'] > 0) ? max(0.0, $t['ttfb_s'] - $t['tls_s']) : max(0.0, $t['ttfb_s'] - $t['conn_s']);
        $xfer = max(0.0, $t['total_s'] - $t['ttfb_s']);

        $breakdown = [
            'dns_ms'      => round($dns * 1000, 2),
            'tcp_ms'      => round($tcp * 1000, 2),
            'tls_ms'      => round($tls * 1000, 2),
            'ttfb_ms'     => round($ttfb * 1000, 2),
            'transfer_ms' => round($xfer * 1000, 2),
            'total_ms'    => round($t['total_s'] * 1000, 2),
        ];
    }

    // TLS cert chain parsing: certinfo contains chain entries when CURLOPT_CERTINFO enabled 【2-f92b92】【1-11de95】
    $certChain = [];
    if (!empty($info['certinfo']) && is_array($info['certinfo'])) {
        foreach ($info['certinfo'] as $idx => $certEntry) {
            // Some builds include a "Cert" field; if present, parse it with openssl_x509_parse. 【5-e31003】【6-a5e8c7】
            $parsed = null;
            if (isset($certEntry['Cert'])) {
                $parsed = @openssl_x509_parse($certEntry['Cert']);
            }
            $certChain[] = [
                'index'  => $idx,
                'raw'    => $certEntry,
                'parsed' => $parsed,
            ];
        }
    }

    $tlsVerbose = parse_tls_from_verbose($verboseText);

    return [
        'request' => [
            'url' => $url,
            'resolved_ip' => $ip,
        ],
        'http' => [
            'status_line' => $statusLine,
            'headers' => $respHeaders,
            'http_code' => $info['http_code'] ?? null,
            'effective_url' => $info['url'] ?? null,
            'primary_ip' => $info['primary_ip'] ?? null,
            'primary_port' => $info['primary_port'] ?? null,
            'redirect_count' => $info['redirect_count'] ?? null,
            'redirect_time' => $info['redirect_time'] ?? null,
        ],
        'timings' => [
            'raw' => $t,
            'breakdown' => $breakdown,
        ],
      'tls' => [
    'ssl_verify_result' => $info['ssl_verify_result'] ?? null,
    // other tls fields here...
],  // <-- closes 'tls' array
];     // <-- closes the main return array
