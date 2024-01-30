<?php

$ipAddress = $_GET['ip'];
$portNumber = intval($_GET['port']);

function isHostReachable($ip) {
    $output = shell_exec("ping -c 5 $ip 2>&1");
    $matchCount = preg_match_all('/time=(\d+\.\d+) ms/', $output, $matches);

    if ($matchCount) {
        $pingTimes = array_map('floatval', $matches[1]);
        $averagePing = array_sum($pingTimes) / count($pingTimes);
        return ['reachable' => true, 'pingTimes' => $pingTimes, 'averagePing' => $averagePing];
    } else {
        return ['reachable' => false];
    }
}

function generatePingTable($pingTimes) {
    $table = "<table>";
    $table .= "<tr><th>Ping</th><th>Host</th><th>Time (ms)</th></tr>";

    foreach ($pingTimes as $index => $pingTime) {
        $table .= "<tr><td>$index</td><td>{$pingTimes['host']}</td><td>$pingTime</td></tr>";
    }

    $table .= "</table>";

    return $table;
}

function scanPort($ip, $port) {
    $hostInfo = isHostReachable($ip);

    if ($hostInfo['reachable']) {
        $connection = @fsockopen($ip, $port, $errno, $errstr, 1);

        if (is_resource($connection)) {
            fclose($connection);
            return [
                'result' => 'Port is open and host is reachable.',
                'isOpen' => true,
                'reachable' => true,
                'pingTable' => generatePingTable($hostInfo['pingTimes']),
                'averagePing' => $hostInfo['averagePing']
            ];
        } else {
            return [
                'result' => 'Port is closed and host is reachable.',
                'isOpen' => false,
                'reachable' => true,
                'pingTable' => generatePingTable($hostInfo['pingTimes']),
                'averagePing' => $hostInfo['averagePing']
            ];
        }
    } else {
        return ['result' => 'Host is not reachable.', 'isOpen' => false, 'reachable' => false];
    }
}

$result = scanPort($ipAddress, $portNumber);
header('Content-Type: application/json');
echo json_encode($result);

?>
