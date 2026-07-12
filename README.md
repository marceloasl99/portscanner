# Authorized Port Check

A small PHP application for checking approved TCP services from the web server that hosts the project.

## Security model

This application is intentionally not an unrestricted port scanner.

- The user must confirm authorization in the browser.
- `scan.php` independently enforces a server-side IP/CIDR allowlist.
- Only ports defined in `config.php` can be tested.
- Each request is limited to a small number of ports.
- A per-session/IP rate limit reduces automated abuse.
- The backend accepts JSON POST requests and uses a CSRF token.
- No shell commands, `ping`, `exec`, or user-controlled URLs are used.
- Connections are pinned directly to an allowlisted IPv4 address.

The consent checkbox is not the security boundary. The allowlist in `config.php` is the security boundary.

## Requirements

- PHP 8.1 or newer.
- A web server with outbound TCP connectivity to the approved targets.
- HTTPS is strongly recommended.
- `fsockopen()` must be enabled.

GitHub Pages cannot execute PHP. Use a PHP-capable host, VM, container, or internal web server.

## Files

```text
/
├── index.html
├── scan.php
├── config.php
├── .htaccess
└── README.md
```

## Configure authorized targets

Open `config.php` and edit `allowed_targets`.

Exact IPv4 example:

```php
'allowed_targets' => [
    ['label' => 'Authorized web server', 'cidr' => '198.51.100.25/32'],
],
```

Authorized network example:

```php
'allowed_targets' => [
    ['label' => 'Authorized lab', 'cidr' => '10.20.30.0/24'],
],
```

Use private ranges only when this application runs inside the authorized private network. Never add an address or network without explicit permission.

The current browser selector supports exact `/32` targets. CIDR ranges are enforced by the backend but intentionally disabled in the browser selector. For a subnet, add each approved device as a separate `/32` entry to keep the UI explicit and auditable.

## Configure services

Edit the `services` array in `config.php`. A port must exist in this array or the backend rejects it.

Presets only group ports already present in `services`.

## Deployment

1. Upload all files to the same directory on a PHP-capable server.
2. Edit `config.php` with authorized `/32` targets.
3. Confirm PHP 8.1+ and `fsockopen()` availability.
4. Enable HTTPS.
5. Open `index.html` through the server.
6. Test only a target you own or are explicitly authorized to assess.

## Result meaning

- **Open:** the PHP server completed a TCP connection.
- **No connection:** the connection failed. This cannot reliably distinguish closed, firewall-filtered, routing failure, or timeout.

The test originates from the PHP server, not from the user's phone or workstation. A private IP refers to the server's network view.

## Important limitations

- TCP only; UDP services are not tested.
- This is a connection check, not service fingerprinting or vulnerability detection.
- No banner grabbing, authentication attempts, packet crafting, or firewall evasion is performed.
- Browser-side controls can be bypassed, so all important restrictions are also enforced in PHP.

## Recommended production hardening

- Place the application behind company authentication or VPN access.
- Restrict inbound access by source IP at the reverse proxy/firewall.
- Restrict outbound traffic from the PHP server to only approved destination IPs and ports.
- Keep PHP and the operating system patched.
- Store `config.php` outside the public web root when the hosting platform supports it.
- Review web server logs and rate-limit events.
- Use a dedicated service account/container with minimal permissions.
