php
header('Content-Type applicationjson');
header('Access-Control-Allow-Origin ');
$host = preg_replace('[^a-zA-Z0-9.-]', '', $_GET['q']  '');
if (!$host) { echo '[]'; exit; }
$ch = curl_init('httpscrt.shq='.urlencode($host).'&output=json');
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=true, CURLOPT_TIMEOUT=10, CURLOPT_USERAGENT='L7Tester2.0']);
$out = curl_exec($ch);
curl_close($ch);
echo $out  '[]';
