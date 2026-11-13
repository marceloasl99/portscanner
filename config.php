<?php
// Port Tools v2 - server configuration. Blocked from web access by .htaccess.
return [
    // Maximum hosts accepted in one POST request (the web UI sends hosts in small batches).
    'max_targets_per_request' => 16,
    // Maximum hosts the web UI will expand from CIDR/range input in one scan.
    'max_total_targets' => 256,
    // Maximum ports per request (presets plus custom ports).
    'max_ports' => 64,
    // Seconds to wait for each TCP connection.
    'timeout' => 1.2,
    // false = refuse private ranges (10/8, 172.16/12, 192.168/16). Use false on a public server.
    'allow_private' => true,
    // Optional shared secret. When not empty, requests must send it in the X-Access-Token header.
    'access_token' => '',
];
