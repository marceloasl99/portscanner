<?php
declare(strict_types=1);

/**
 * Port Tools v2 - remote TCP connection checker.
 *
 * GET  scan.php  -> service catalogue, presets and limits.
 * POST scan.php  -> {"targets": ["10.0.0.5", "10.0.0.0/28", "10.0.0.1-10"], "ports": [22, 80, "8000-8010"]}
 *
 * Only scan systems you own or have explicit permission to test.
 */

ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

const VERSION = '2.0.0';

$defaults = [
    'max_targets_per_request' => 16,
    'max_total_targets'       => 256,
    'max_ports'               => 64,
    'timeout'                 => 1.2,
    'allow_private'           => true,
    'access_token'            => '',
];
$config = $defaults;
$configFile = __DIR__ . '/config.php';
if (is_file($configFile)) {
    $loaded = @include $configFile;
    if (is_array($loaded)) {
        $config = array_replace($defaults, $loaded);
    }
}

$services = [
    20 => 'FTP Data', 21 => 'FTP Control', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP', 53 => 'DNS (TCP)',
    80 => 'HTTP', 110 => 'POP3', 111 => 'RPC portmapper', 123 => 'NTP (TCP)', 135 => 'MS RPC',
    139 => 'NetBIOS', 143 => 'IMAP', 161 => 'SNMP (TCP)', 389 => 'LDAP', 443 => 'HTTPS', 445 => 'SMB',
    465 => 'SMTPS', 502 => 'Modbus TCP', 587 => 'SMTP Submission', 636 => 'LDAPS', 993 => 'IMAPS',
    995 => 'POP3S', 1433 => 'Microsoft SQL Server', 1521 => 'Oracle', 1883 => 'MQTT', 2049 => 'NFS',
    2375 => 'Docker API (plain)', 3000 => 'Dev server', 3306 => 'MySQL', 3389 => 'RDP',
    4840 => 'OPC UA', 5432 => 'PostgreSQL', 5672 => 'RabbitMQ', 5900 => 'VNC', 6379 => 'Redis',
    8000 => 'HTTP Dev', 8080 => 'HTTP Alternate', 8443 => 'HTTPS Alternate', 8883 => 'MQTT TLS',
    9200 => 'Elasticsearch', 11211 => 'Memcached', 27017 => 'MongoDB',
];

$presets = [
    'common'     => ['label' => 'Common',           'ports' => [22, 53, 80, 443, 445, 3389]],
    'web'        => ['label' => 'Web',              'ports' => [80, 443, 3000, 8000, 8080, 8443]],
    'remote'     => ['label' => 'Remote access',    'ports' => [22, 23, 3389, 5900]],
    'windows'    => ['label' => 'Windows',          'ports' => [135, 139, 445, 3389]],
    'mail'       => ['label' => 'Mail',             'ports' => [25, 110, 143, 465, 587, 993, 995]],
    'database'   => ['label' => 'Databases',        'ports' => [1433, 1521, 3306, 5432, 6379, 27017]],
    'services'   => ['label' => 'Exposed services', 'ports' => [2049, 2375, 5672, 9200, 11211]],
    'industrial' => ['label' => 'Industrial / IoT', 'ports' => [502, 1883, 4840, 8883]],
];

// Open ports that deserve attention when reachable from elsewhere. high / medium; everything else is low.
$risk = [
    21 => ['high', 'FTP sends passwords in clear text.'],
    23 => ['high', 'Telnet sends everything in clear text.'],
    135 => ['medium', 'Windows RPC should not be reachable from untrusted networks.'],
    139 => ['medium', 'Legacy NetBIOS file sharing.'],
    445 => ['high', 'SMB exposed; frequent target of ransomware and worms.'],
    1433 => ['medium', 'Database port reachable over the network.'],
    1521 => ['medium', 'Database port reachable over the network.'],
    2049 => ['medium', 'NFS shares reachable over the network.'],
    2375 => ['high', 'Docker API without TLS gives full control of the host.'],
    3306 => ['medium', 'Database port reachable over the network.'],
    3389 => ['high', 'RDP exposed; common brute-force and ransomware entry point.'],
    5432 => ['medium', 'Database port reachable over the network.'],
    5900 => ['high', 'VNC is often unauthenticated or weakly protected.'],
    6379 => ['high', 'Redis is usually unauthenticated by default.'],
    9200 => ['high', 'Elasticsearch is often exposed without authentication.'],
    11211 => ['high', 'Memcached exposed; also abused for amplification attacks.'],
    27017 => ['high', 'MongoDB reachable over the network.'],
    502 => ['high', 'Modbus has no authentication.'],
    1883 => ['medium', 'MQTT without TLS.'],
];

function out(int $status, array $data): never
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function fail(int $status, string $message): never
{
    out($status, ['ok' => false, 'error' => $message]);
}

/** Addresses that are never scanned, whatever the configuration says. */
function isForbidden(int $ip, bool $allowPrivate): ?string
{
    $ranges = [
        ['0.0.0.0', 8, 'this-network addresses'],
        ['127.0.0.0', 8, 'loopback addresses'],
        ['169.254.0.0', 16, 'link-local addresses (cloud metadata)'],
        ['224.0.0.0', 4, 'multicast and reserved addresses'],
    ];
    if (!$allowPrivate) {
        $ranges[] = ['10.0.0.0', 8, 'private addresses'];
        $ranges[] = ['172.16.0.0', 12, 'private addresses'];
        $ranges[] = ['192.168.0.0', 16, 'private addresses'];
    }
    foreach ($ranges as [$base, $bits, $label]) {
        $mask = $bits === 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;
        if (($ip & $mask) === (ip2long($base) & $mask)) {
            return $label;
        }
    }
    return null;
}

/** Expands "1.2.3.4", "1.2.3.0/28", "1.2.3.1-20" or "1.2.3.1-1.2.3.20" into integer addresses. */
function expandTarget(string $spec, int $limit): array
{
    $spec = trim($spec);
    $v4 = static fn(string $s): bool => filter_var($s, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;

    if ($v4($spec)) {
        return [ip2long($spec)];
    }
    if (preg_match('#^([\d.]+)/(\d{1,2})$#', $spec, $m) && $v4($m[1]) && (int)$m[2] >= 0 && (int)$m[2] <= 32) {
        $bits = (int)$m[2];
        $size = 2 ** (32 - $bits);
        if ($size > $limit) {
            fail(422, "Range $spec has $size addresses; the limit is $limit.");
        }
        $start = ip2long($m[1]) & ((~0 << (32 - $bits)) & 0xFFFFFFFF);
        // Skip network and broadcast addresses on subnets larger than /31.
        $from = $bits <= 30 ? 1 : 0;
        $to = $bits <= 30 ? $size - 2 : $size - 1;
        return range($start + $from, $start + $to);
    }
    if (preg_match('#^([\d.]+)-([\d.]+)$#', $spec, $m) && $v4($m[1])) {
        $first = ip2long($m[1]);
        if ($v4($m[2])) {
            $last = ip2long($m[2]);
        } elseif (ctype_digit($m[2]) && (int)$m[2] <= 255) {
            $last = ($first & 0xFFFFFF00) | (int)$m[2];
        } else {
            fail(422, "Invalid range: $spec");
        }
        if ($last < $first) {
            fail(422, "Range $spec ends before it starts.");
        }
        if ($last - $first + 1 > $limit) {
            fail(422, "Range $spec has more than $limit addresses.");
        }
        return range($first, $last);
    }
    fail(422, "Invalid IPv4 address or range: $spec");
}

function parseTargets(mixed $value, array $config): array
{
    if (is_string($value)) {
        $value = preg_split('/[\s,;]+/', trim($value), -1, PREG_SPLIT_NO_EMPTY);
    }
    if (!is_array($value) || !$value) {
        fail(422, 'Enter at least one IPv4 address.');
    }
    $limit = (int)$config['max_targets_per_request'];
    $ips = [];
    foreach ($value as $spec) {
        foreach (expandTarget((string)$spec, $limit) as $n) {
            $ips[$n] = $n;
        }
        if (count($ips) > $limit) {
            fail(422, "Maximum {$limit} targets per request.");
        }
    }
    $result = [];
    foreach ($ips as $n) {
        $reason = isForbidden($n, (bool)$config['allow_private']);
        if ($reason !== null) {
            fail(422, long2ip($n) . " is not allowed: $reason are not scanned.");
        }
        $result[] = long2ip($n);
    }
    return $result;
}

function parsePorts(mixed $value, array $config): array
{
    if (is_string($value)) {
        $value = preg_split('/[\s,;]+/', trim($value), -1, PREG_SPLIT_NO_EMPTY);
    }
    if (!is_array($value) || !$value) {
        fail(422, 'Select at least one port.');
    }
    $ports = [];
    foreach ($value as $item) {
        $item = is_int($item) ? (string)$item : trim((string)$item);
        if (preg_match('/^(\d{1,5})(?:-(\d{1,5}))?$/', $item, $m)) {
            $a = (int)$m[1];
            $b = isset($m[2]) ? (int)$m[2] : $a;
            if ($a < 1 || $b > 65535 || $b < $a) {
                fail(422, "Invalid port or range: $item");
            }
            if ($b - $a + 1 > (int)$config['max_ports']) {
                fail(422, "Range $item exceeds the limit of {$config['max_ports']} ports.");
            }
            for ($p = $a; $p <= $b; $p++) {
                $ports[$p] = $p;
            }
        } else {
            fail(422, "Invalid port: $item");
        }
        if (count($ports) > (int)$config['max_ports']) {
            fail(422, "Maximum {$config['max_ports']} ports per request.");
        }
    }
    sort($ports);
    return array_values($ports);
}

/** Opens connections to all ports of one host in parallel, then classifies each one. */
function checkHost(string $ip, array $ports, float $timeout, array $services, array $risk): array
{
    $pending = [];
    $items = [];
    $started = [];
    foreach ($ports as $port) {
        $errno = 0;
        $err = '';
        $s = @stream_socket_client("tcp://$ip:$port", $errno, $err, $timeout, STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT);
        $started[$port] = hrtime(true);
        if ($s === false) {
            $items[$port] = ['status' => 'no_connection', 'ms' => round((hrtime(true) - $started[$port]) / 1e6, 1)];
            continue;
        }
        stream_set_blocking($s, false);
        $pending[$port] = $s;
    }

    $deadline = hrtime(true) + (int)($timeout * 1e9);
    while ($pending && hrtime(true) < $deadline) {
        $write = array_values($pending);
        $read = $except = null;
        $left = max(0, $deadline - hrtime(true));
        if (@stream_select($read, $write, $except, intdiv((int)$left, 1_000_000_000), intdiv((int)$left % 1_000_000_000, 1000)) === false) {
            break;
        }
        foreach ($write ?? [] as $s) {
            $port = array_search($s, $pending, true);
            $ms = round((hrtime(true) - $started[$port]) / 1e6, 1);
            // A refused connection also becomes "writable"; the peer name only exists if it connected.
            $items[$port] = ['status' => @stream_socket_get_name($s, true) !== false ? 'open' : 'no_connection', 'ms' => $ms];
            fclose($s);
            unset($pending[$port]);
        }
    }
    foreach ($pending as $port => $s) {
        $items[$port] = ['status' => 'no_connection', 'ms' => round($timeout * 1000, 1)];
        fclose($s);
    }

    $rows = [];
    foreach ($ports as $port) {
        $r = $items[$port];
        $open = $r['status'] === 'open';
        $level = $open ? ($risk[$port][0] ?? 'low') : 'none';
        $rows[] = [
            'port'    => $port,
            'service' => $services[$port] ?? 'Unknown',
            'status'  => $r['status'],
            'ms'      => $r['ms'],
            'message' => $open ? 'TCP connection established' : 'Closed, filtered, unreachable, or timed out',
            'risk'    => $level,
            'note'    => $open ? ($risk[$port][1] ?? '') : '',
        ];
    }
    return $rows;
}

// ---------------------------------------------------------------- routing

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($config['access_token'] !== '') {
    $sent = (string)($_SERVER['HTTP_X_ACCESS_TOKEN'] ?? '');
    if (!hash_equals((string)$config['access_token'], $sent)) {
        fail(401, 'Access token required.');
    }
}

if ($method === 'GET') {
    out(200, [
        'ok'       => true,
        'version'  => VERSION,
        'services' => $services,
        'presets'  => $presets,
        'risk'     => array_map(static fn(array $r): string => $r[0], $risk),
        'limits'   => [
            'targetsPerRequest' => (int)$config['max_targets_per_request'],
            'totalTargets'      => (int)$config['max_total_targets'],
            'ports'             => (int)$config['max_ports'],
        ],
        'tokenRequired' => $config['access_token'] !== '',
    ]);
}
if ($method !== 'POST') {
    fail(405, 'Method not allowed.');
}
if (!str_starts_with(strtolower($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json')) {
    fail(415, 'JSON required.');
}
$raw = file_get_contents('php://input');
if (!is_string($raw) || strlen($raw) > 32768) {
    fail(400, 'Invalid request.');
}
try {
    $body = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
} catch (JsonException) {
    fail(400, 'Invalid JSON.');
}
if (!is_array($body)) {
    fail(400, 'Invalid request.');
}

$ips = parseTargets($body['targets'] ?? null, $config);
$ports = parsePorts($body['ports'] ?? null, $config);

$start = hrtime(true);
$groups = [];
$open = 0;
$failed = 0;
$flagged = 0;
foreach ($ips as $ip) {
    $rows = checkHost($ip, $ports, (float)$config['timeout'], $services, $risk);
    foreach ($rows as $r) {
        if ($r['status'] === 'open') {
            $open++;
            if ($r['risk'] === 'high' || $r['risk'] === 'medium') {
                $flagged++;
            }
        } else {
            $failed++;
        }
    }
    $groups[] = ['ip' => $ip, 'ports' => $rows];
}

out(200, [
    'ok'        => true,
    'version'   => VERSION,
    'protocol'  => 'TCP',
    'summary'   => [
        'targets'      => count($ips),
        'checks'       => count($ips) * count($ports),
        'open'         => $open,
        'noConnection' => $failed,
        'flagged'      => $flagged,
        'durationMs'   => round((hrtime(true) - $start) / 1e6, 1),
    ],
    'results'   => $groups,
    'timestamp' => date(DATE_ATOM),
]);
