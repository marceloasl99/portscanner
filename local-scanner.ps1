# Local Port Inspector - no cloud, no host, no network scan
# Shows TCP ports currently listening on this Windows computer.
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$report = Join-Path $PSScriptRoot "local-ports-$stamp.html"

function Get-ServiceName([int]$Port) {
    $map = @{20='FTP Data';21='FTP';22='SSH';23='Telnet';25='SMTP';53='DNS';80='HTTP';110='POP3';123='NTP';135='MS RPC';139='NetBIOS';143='IMAP';161='SNMP';389='LDAP';443='HTTPS';445='SMB';465='SMTPS';502='Modbus TCP';587='SMTP Submission';636='LDAPS';993='IMAPS';995='POP3S';1433='Microsoft SQL Server';1521='Oracle';1883='MQTT';3306='MySQL';3389='RDP';4840='OPC UA';5432='PostgreSQL';5900='VNC';8080='HTTP Alternate';8443='HTTPS Alternate';8883='MQTT TLS'}
    if ($map.ContainsKey($Port)) { return $map[$Port] }
    return 'Other'
}

try {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort,LocalAddress
} catch {
    $listeners = netstat -ano -p tcp | Select-String 'LISTENING' | ForEach-Object {
        $parts = ($_ -replace '^\s+','') -split '\s+'
        $endpoint = $parts[1]
        $lastColon = $endpoint.LastIndexOf(':')
        [pscustomobject]@{LocalAddress=$endpoint.Substring(0,$lastColon).Trim('[',']');LocalPort=[int]$endpoint.Substring($lastColon+1);OwningProcess=[int]$parts[-1];State='Listen'}
    } | Sort-Object LocalPort,LocalAddress
}

$rows = foreach ($item in $listeners) {
    $processName = 'Unavailable'
    try { $processName = (Get-Process -Id $item.OwningProcess -ErrorAction Stop).ProcessName } catch {}
    [pscustomobject]@{
        Port = [int]$item.LocalPort
        Service = Get-ServiceName ([int]$item.LocalPort)
        Address = [string]$item.LocalAddress
        Scope = if ($item.LocalAddress -in @('127.0.0.1','::1')) {'Localhost only'} elseif ($item.LocalAddress -in @('0.0.0.0','::')) {'All interfaces'} else {'Specific interface'}
        PID = [int]$item.OwningProcess
        Process = $processName
    }
}

Write-Host ''
Write-Host 'LOCAL TCP LISTENING PORTS' -ForegroundColor Cyan
Write-Host ('Computer: ' + $env:COMPUTERNAME)
Write-Host ('Generated: ' + (Get-Date))
Write-Host ''
$rows | Format-Table Port,Service,Address,Scope,PID,Process -AutoSize

$style = @'
<style>body{font-family:Segoe UI,Arial;background:#f4f7fb;color:#172033;margin:0;padding:24px}.wrap{max-width:1100px;margin:auto}.card{background:white;border:1px solid #dce3ec;border-radius:16px;padding:20px;box-shadow:0 6px 20px #0f172a12}h1{margin-top:0}p{color:#64748b}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #e5e7eb}th{background:#eff6ff}tr:hover{background:#f8fafc}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#dcfce7;color:#166534;font-weight:600}@media(max-width:700px){body{padding:10px}.card{padding:12px;overflow:auto}th,td{white-space:nowrap}}</style>
'@
$pre = "<div class='wrap'><div class='card'><h1>Local TCP Listening Ports</h1><p><strong>Computer:</strong> $env:COMPUTERNAME<br><strong>Generated:</strong> $(Get-Date)<br><strong>Total:</strong> $($rows.Count)</p>"
$post = "</div></div>"
$table = $rows | ConvertTo-Html -Fragment | Out-String
$html = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Local Port Report</title>$style</head><body>$pre$table$post</body></html>"
[IO.File]::WriteAllText($report,$html,[Text.UTF8Encoding]::new($false))
Write-Host ''
Write-Host ('HTML report: ' + $report) -ForegroundColor Green
Start-Process $report
Read-Host 'Press Enter to close'
