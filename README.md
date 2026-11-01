# Port Tools

An experimental toolkit with two independent modes:

1. **Remote IP scan** (`index.html` + `scan.php`): the browser sends IPv4 addresses and TCP ports to a PHP server, which runs TCP connection checks and returns a report.
2. **Local computer inspector** (`local-scanner.ps1`): a PowerShell script that collects listening ports, connections, processes, network configuration, hosts file and firewall rules, then writes one interactive HTML report. Nothing leaves the machine.

> Only scan systems you own or have explicit permission to test.

## Files

```text
/
├── index.html            Web UI (tabs: remote scan and this computer)
├── scan.php              Remote scan backend (requires PHP)
├── local-scanner.ps1     Local inspector: collects data and builds the HTML report
├── Run-local-scan.bat    Double-click launcher for the local inspector
├── config.php            Project configuration
├── .htaccess, .gitattributes, README.md
```

## Local inspector (recommended)

1. In the **This computer** tab of `index.html`, download `Run-local-scan.bat` and `local-scanner.ps1` into the same folder.
2. Double-click `Run-local-scan.bat`.
3. The report `local-ports-YYYY-MM-DD_HH-mm-ss.html` opens in your browser and is saved in that folder.

From PowerShell instead:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\local-scanner.ps1
```

Optional traffic capture (requires PowerShell as administrator):

```powershell
.\local-scanner.ps1 -CaptureSeconds 30
```

This writes `capture-*.etl` and `capture-*.pcapng` (open the `.pcapng` in Wireshark). Not tested in this environment because it needs administrator rights.

### What the report contains

- **Overview**: summary cards, primary network (interface, IP, gateway, DNS), prioritized findings (high, medium, info), most active processes and most used remote services.
- **Ports**: TCP and UDP listeners with likely service, likely use (estimated from the port), scope (localhost only, all interfaces, specific interface), risk level and owning process. Filters for protocol, scope and risk.
- **Connections**: TCP sockets with local and remote endpoints, state, process, direction and estimated remote service.
- **Processes**: PID, name, estimated purpose, executable path, command line, ports and connections.
- **Network**: adapters and MAC addresses, IP addresses, neighbors (ARP), routes, DNS servers, raw `ipconfig /all` and `route print` output.
- **Hosts**: the Windows `hosts` file, with active entries highlighted.
- **Firewall**: profile status and default actions, and inbound allow rules, marked as "broad" (any port and any program) or as matching a port that is currently listening.
- **Capture**: status and instructions for the optional traffic capture.

Use the **Expand** and **Collapse** buttons to open or close all details. Click a row to see its details. Press `/` to search. The **Theme** button switches between dark (default) and light.

### Limitations

- "Likely use" and "purpose" are **estimates** based on port number, process name and executable path. They are not proof.
- The risk level is heuristic: it combines exposure scope with a list of services that are commonly risky when exposed.
- Without administrator rights, some process paths, command lines and firewall rules are unavailable.
- The script performs no reverse DNS lookups and no other network requests. Remote host names are not resolved.

## Remote scan (requires PHP)

Requirements: PHP 8.1 or newer, `fsockopen()` enabled, and `index.html` and `scan.php` in the same folder.

GitHub Pages can display `index.html` but cannot run `scan.php`, so remote scanning needs PHP hosting. Not yet tested here because PHP is not installed.

Results:

- **Open:** the PHP server completed a TCP connection.
- **No connection:** closed, filtered, unreachable or timed out.

## Change history

1. Cloned `github.com/marceloasl99/portscanner` into `C:\33\4\portscanner`.
2. First local inspector: listening TCP ports with likely service and process, written to a simple HTML report.
3. Detailed report: address, scope, risk level with notes, executable path and command line, established connections, filter and grouping by process. Added `Run-local-scan.bat` and the **This computer** tab in `index.html`.
4. Network and firewall collection: `ipconfig /all`, adapters and MAC addresses, IP addresses, ARP neighbors, `route print`, the `hosts` file, firewall profiles and inbound allow rules.
5. Rebuilt the report as an interactive web UI: overview with navigation cards, sections (Ports, Connections, Processes, Network, Hosts, Firewall, Capture), expandable details, estimated use and purpose, prioritized findings and optional capture with `pktmon`.
6. Fixed a PowerShell variable collision (`$L`/`$l`, `$C`/`$c`, `$P`/`$p`) that zeroed counts, and saved the script with a UTF-8 BOM so accents render correctly.
7. Restyled the report to a black-and-white design with a light theme, a sticky header, per-table search, keyboard support and a copy button for raw output.

## Plan and next steps

- [ ] Install PHP and test remote scanning (`php -S localhost:8000` in the project folder).
- [ ] Test traffic capture from an elevated PowerShell and confirm the `pktmon` options (`--pkt-size`, `-f`, `etl2pcap`).
- [ ] Run the inspector as administrator and confirm paths and command lines for all processes.
- [ ] Review the firewall table (hundreds of rules) and consider collapsing it by default.
- [ ] Add a traffic summary from the capture (top destinations and ports) without requiring Wireshark.
- [ ] Expand the port and process knowledge base based on real results.
- [ ] Check the report layout in a browser on desktop and phone widths.

## Interpretation

- `127.0.0.1` or `::1`: localhost only.
- `0.0.0.0` or `::`: all interfaces.
- Listening locally does not mean reachable from outside. The firewall may still block it.
