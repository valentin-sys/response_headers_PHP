<?php
// Start time for latency calculation
$start_time = microtime(true);

// Simulate some processing (optional)
usleep(100000); // 100 milliseconds

// Calculate latency
$latency = microtime(true) - $start_time;

// Get HTTP status
$http_status = http_response_code();

echo '<h1>Response Headers</h1>';
echo '<pre>';
print_r(getallheaders());
echo '</pre>';

echo '<h1>Request Information</h1>';
echo '<p>Request Method: ' . $_SERVER['REQUEST_METHOD'] . '</p>';
echo '<p>Request URL: ' . $_SERVER['REQUEST_URI'] . '</p>';
echo '<p>Client IP: ' . $_SERVER['REMOTE_ADDR'] . '</p>';
echo '<p>User Agent: ' . $_SERVER['HTTP_USER_AGENT'] . '</p>';

echo '<h1>Server Information</h1>';
echo '<p>Server Time: ' . date('Y-m-d H:i:s') . '</p>';
echo '<p>Server Name: ' . $_SERVER['SERVER_NAME'] . '</p>';
echo '<p>Latency: ' . round($latency * 1000, 2) . ' ms</p>';
echo '<p>HTTP Status: ' . $http_status . '</p>';

echo '<h1>Cookies</h1>';
echo '<pre>';
print_r($_COOKIE);
echo '</pre>';
?>
