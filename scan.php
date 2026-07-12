<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
session_name('portcheck_session');
session_set_cookie_params(['httponly'=>true, 'secure'=>(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'), 'samesite'=>'Strict']);
session_start();

$config = require __DIR__ . '/config.php';

function reply(int $status, array $data): never {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function clientKey(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return hash('sha256', $ip . '|' . session_id());
}
function applyRateLimit(array $rule): void {
    $dir = sys_get_temp_dir() . '/authorized_portcheck';
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) reply(503, ['ok'=>false,'error'=>'Rate-limit storage is unavailable.']);
    $file = $dir . '/' . clientKey() . '.json';
    $fh = @fopen($file, 'c+');
    if (!$fh || !flock($fh, LOCK_EX)) reply(503, ['ok'=>false,'error'=>'Rate-limit check is unavailable.']);
    $raw = stream_get_contents($fh); $now = time();
    $times = is_string($raw) && $raw !== '' ? json_decode($raw, true) : [];
    if (!is_array($times)) $times = [];
    $window = (int)$rule['window_seconds']; $max = (int)$rule['requests'];
    $times = array_values(array_filter($times, fn($t) => is_int($t) && $t > $now - $window));
    if (count($times) >= $max) { flock($fh, LOCK_UN); fclose($fh); reply(429, ['ok'=>false,'error'=>'Too many requests. Wait and try again.','retryAfterSeconds'=>$window]); }
    $times[] = $now; rewind($fh); ftruncate($fh, 0); fwrite($fh, json_encode($times)); fflush($fh); flock($fh, LOCK_UN); fclose($fh);
}
function ipv4ToUnsigned(string $ip): int|false {
    $long = ip2long($ip); return $long === false ? false : (int)sprintf('%u', $long);
}
function ipInCidr(string $ip, string $cidr): bool {
    if (!str_contains($cidr, '/')) $cidr .= '/32';
    [$network, $prefixText] = explode('/', $cidr, 2);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) return false;
    if (!ctype_digit($prefixText)) return false;
    $prefix = (int)$prefixText; if ($prefix < 0 || $prefix > 32) return false;
    $ipN = ipv4ToUnsigned($ip); $netN = ipv4ToUnsigned($network); if ($ipN === false || $netN === false) return false;
    $mask = $prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF);
    return (($ipN & $mask) === ($netN & $mask));
}
function authorizedTarget(string $ip, array $targets): ?array {
    foreach ($targets as $target) if (isset($target['cidr']) && ipInCidr($ip, (string)$target['cidr'])) return $target;
    return null;
}
function csrfToken(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function scanTcp(string $ip, int $port, float $timeout, string $service): array {
    $started = hrtime(true); $errno = 0; $errstr = '';
    set_error_handler(static fn() => true);
    $socket = fsockopen($ip, $port, $errno, $errstr, $timeout);
    restore_error_handler();
    $elapsed = round((hrtime(true) - $started) / 1e6, 1);
    if (is_resource($socket)) { fclose($socket); return ['port'=>$port,'service'=>$service,'status'=>'open','connectionTimeMs'=>$elapsed,'summary'=>'TCP connection established']; }
    return ['port'=>$port,'service'=>$service,'status'=>'unreachable','connectionTimeMs'=>$elapsed,'summary'=>'No TCP connection (closed, filtered, or timed out)'];
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $targets = array_map(fn($t) => ['label'=>(string)($t['label'] ?? 'Authorized target'),'cidr'=>(string)($t['cidr'] ?? '')], $config['allowed_targets']);
    reply(200, ['ok'=>true,'appName'=>$config['app_name'],'csrfToken'=>csrfToken(),'targets'=>$targets,'services'=>$config['services'],'presets'=>$config['presets'],'maxPortsPerRequest'=>$config['max_ports_per_request']]);
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') reply(405, ['ok'=>false,'error'=>'Method not allowed.']);
applyRateLimit($config['rate_limit']);
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
if (!str_starts_with(strtolower($contentType), 'application/json')) reply(415, ['ok'=>false,'error'=>'Content-Type must be application/json.']);
$raw = file_get_contents('php://input');
if (!is_string($raw) || strlen($raw) > 8192) reply(400, ['ok'=>false,'error'=>'Invalid request body.']);
try { $body = json_decode($raw, true, 32, JSON_THROW_ON_ERROR); } catch (JsonException) { reply(400, ['ok'=>false,'error'=>'Invalid JSON.']); }
if (!is_array($body)) reply(400, ['ok'=>false,'error'=>'Invalid request.']);
$token = (string)($body['csrfToken'] ?? '');
if (!hash_equals(csrfToken(), $token)) reply(403, ['ok'=>false,'error'=>'Session validation failed. Refresh the page.']);
if (($body['consent'] ?? false) !== true) reply(403, ['ok'=>false,'error'=>'Authorization confirmation is required.']);
$ip = trim((string)($body['ip'] ?? ''));
if (str_contains($ip, "\0") || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) reply(422, ['ok'=>false,'error'=>'Enter a valid IPv4 address.']);
$target = authorizedTarget($ip, $config['allowed_targets']);
if ($target === null) reply(403, ['ok'=>false,'error'=>'This IP address is not in the server allowlist.']);
$inputPorts = $body['ports'] ?? [];
if (!is_array($inputPorts) || $inputPorts === []) reply(422, ['ok'=>false,'error'=>'Select at least one approved port.']);
$ports = [];
foreach ($inputPorts as $value) {
    if (is_int($value)) $port = $value; elseif (is_string($value) && ctype_digit($value)) $port = (int)$value; else reply(422, ['ok'=>false,'error'=>'Invalid port value.']);
    if (!array_key_exists($port, $config['services'])) reply(403, ['ok'=>false,'error'=>"Port {$port} is not enabled by the server policy."]);
    $ports[$port] = $port;
}
$ports = array_values($ports); sort($ports);
if (count($ports) > (int)$config['max_ports_per_request']) reply(422, ['ok'=>false,'error'=>'Too many ports selected.']);
$results = [];
foreach ($ports as $port) $results[] = scanTcp($ip, $port, (float)$config['connect_timeout_seconds'], (string)$config['services'][$port]);
$open = count(array_filter($results, fn($r) => $r['status'] === 'open'));
reply(200, ['ok'=>true,'target'=>['ip'=>$ip,'label'=>(string)($target['label'] ?? 'Authorized target')],'authorization'=>'Confirmed by user and enforced by server allowlist','protocol'=>'TCP','summary'=>['tested'=>count($results),'open'=>$open,'noConnection'=>count($results)-$open],'results'=>$results,'timestamp'=>date(DATE_ATOM)]);
