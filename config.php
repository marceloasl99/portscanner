<?php
declare(strict_types=1);

/*
 * SERVER-SIDE SECURITY POLICY
 * Add only IP addresses/CIDR networks you own or are explicitly authorized to test.
 * The browser consent checkbox is informational; this allowlist is the enforced control.
 * Examples below are documentation ranges and will not reach real devices.
 */
return [
    'app_name' => 'Authorized Port Check',
    'allowed_targets' => [
        // ['label' => 'Authorized web server', 'cidr' => '203.0.113.10/32'],
        // ['label' => 'Authorized OT test network', 'cidr' => '192.0.2.0/28'],
    ],
    'services' => [
        20 => 'FTP Data', 21 => 'FTP Control', 22 => 'SSH', 23 => 'Telnet',
        25 => 'SMTP', 53 => 'DNS (TCP)', 80 => 'HTTP', 110 => 'POP3',
        135 => 'MS RPC', 139 => 'NetBIOS', 143 => 'IMAP', 389 => 'LDAP',
        443 => 'HTTPS', 445 => 'SMB', 465 => 'SMTPS', 502 => 'Modbus TCP',
        587 => 'SMTP Submission', 636 => 'LDAPS', 993 => 'IMAPS', 995 => 'POP3S',
        1433 => 'Microsoft SQL Server', 1521 => 'Oracle', 1883 => 'MQTT',
        3306 => 'MySQL', 3389 => 'RDP', 4840 => 'OPC UA', 5432 => 'PostgreSQL',
        5900 => 'VNC', 8080 => 'HTTP Alternate', 8443 => 'HTTPS Alternate',
        8883 => 'MQTT TLS'
    ],
    'presets' => [
        'web' => ['label' => 'Web', 'ports' => [80, 443, 8080, 8443]],
        'remote' => ['label' => 'Remote access', 'ports' => [22, 23, 3389, 5900]],
        'windows' => ['label' => 'Windows services', 'ports' => [135, 139, 445, 3389]],
        'mail' => ['label' => 'Email', 'ports' => [25, 110, 143, 465, 587, 993, 995]],
        'database' => ['label' => 'Databases', 'ports' => [1433, 1521, 3306, 5432]],
        'industrial' => ['label' => 'Industrial / IoT', 'ports' => [502, 1883, 4840, 8883]],
    ],
    'connect_timeout_seconds' => 1.5,
    'max_ports_per_request' => 12,
    'rate_limit' => ['requests' => 6, 'window_seconds' => 60],
];
