# Port Tools

A complete experimental project with two independent modes.

## 1. Scan IP addresses

The browser sends selected IPv4 addresses and standard TCP ports to `scan.php`. The PHP server performs TCP connection checks and returns a clear report.

## 2. Inspect this computer locally

`local-scanner.ps1` runs directly on Windows and lists TCP ports currently in the `Listen` state. This mode does not send IP addresses, ports, process names, or results to the website, PHP host, or cloud.

A normal browser cannot inspect operating-system TCP listeners directly. The local PowerShell script is therefore required for a real local-only result.

## Files

```text
/
├── index.html
├── scan.php
├── local-scanner.ps1
└── README.md
```

## Server mode requirements

- PHP 8.1 or newer
- `fsockopen()` enabled
- `index.html` and `scan.php` in the same directory

GitHub Pages can display `index.html` but cannot execute `scan.php`. Remote mode requires PHP hosting. The local PowerShell mode can still be downloaded from static hosting.

## Local Windows mode

1. Download `local-scanner.ps1` from the **This computer** tab.
2. Right-click it and choose **Run with PowerShell**.
3. If blocked, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\local-scanner.ps1
```

The script:

- Uses `Get-NetTCPConnection -State Listen`.
- Falls back to `netstat -ano -p tcp` if required.
- Shows local address, TCP port, scope, PID, process, and likely service.
- Writes and opens `local-ports-YYYY-MM-DD_HH-mm-ss.html` beside the script.
- Makes no network request and has no upload code.

Administrator rights are not normally required to list ports, but process names may be unavailable for processes the current account cannot inspect.

## Authorization

Only scan systems you own or have explicit permission to test. Clicking the remote scan button confirms that authorization.

## Result interpretation

- **Open:** the PHP server completed a TCP connection.
- **No connection:** closed, filtered, unreachable, or timed out.
- **Listening locally:** Windows reports that a local process is accepting TCP connections on that address and port.

An address of `127.0.0.1` or `::1` is localhost-only. `0.0.0.0` or `::` generally indicates all local interfaces. Firewall policy may still control actual remote access.
