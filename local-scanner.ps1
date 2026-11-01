#requires -Version 5.1
# Local Network Inspector - runs only on this computer.
# Collects listening and connected sockets, processes, network configuration and firewall data,
# then writes one interactive HTML report. This script makes no outbound request and uploads nothing.
#
# Optional traffic capture (needs an elevated PowerShell):
#   .\local-scanner.ps1 -CaptureSeconds 30
param([int]$CaptureSeconds = 0)

$ErrorActionPreference = 'Continue'
$generated = Get-Date
$stamp = $generated.ToString('yyyy-MM-dd_HH-mm-ss')
$report = Join-Path $PSScriptRoot "local-ports-$stamp.html"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------- Knowledge base (estimates, not verdicts) ----------------
# port => @(service, typical use, protocol)
$portKB = @{
    20=@('FTP dados','Transferência de arquivos (modo ativo)','TCP');
    21=@('FTP','Transferência de arquivos em texto claro','TCP');
    22=@('SSH','Acesso remoto seguro a terminal','TCP');
    23=@('Telnet','Terminal remoto em texto claro (inseguro)','TCP');
    25=@('SMTP','Envio de e-mail entre servidores','TCP');
    53=@('DNS','Resolução de nomes de domínio','TCP/UDP');
    67=@('DHCP servidor','Distribui endereços IP automaticamente','UDP');
    68=@('DHCP cliente','Recebe endereço IP automaticamente','UDP');
    69=@('TFTP','Transferência simples de arquivos (boot de equipamentos)','UDP');
    80=@('HTTP','Web sem criptografia','TCP');
    110=@('POP3','Recebimento de e-mail','TCP');
    123=@('NTP','Sincronização de horário','UDP');
    135=@('MS RPC','Chamadas remotas do Windows (serviços, DCOM)','TCP');
    137=@('NetBIOS nomes','Nomes de rede legados do Windows','UDP');
    138=@('NetBIOS datagrama','Navegação legada em redes Windows','UDP');
    139=@('NetBIOS sessão','Compartilhamento legado do Windows','TCP');
    143=@('IMAP','Acesso a e-mail','TCP');
    161=@('SNMP','Monitoramento de equipamentos de rede','UDP');
    162=@('SNMP trap','Alertas de equipamentos de rede','UDP');
    389=@('LDAP','Diretório de usuários (Active Directory)','TCP/UDP');
    443=@('HTTPS','Web criptografada (sites, APIs, apps)','TCP');
    445=@('SMB','Compartilhamento de arquivos e impressoras Windows','TCP');
    465=@('SMTPS','Envio de e-mail seguro','TCP');
    500=@('IKE/IPsec','Negociação de VPN IPsec','UDP');
    514=@('Syslog','Envio de logs','UDP');
    587=@('SMTP submissão','Envio de e-mail autenticado','TCP');
    636=@('LDAPS','Diretório seguro','TCP');
    993=@('IMAPS','E-mail seguro','TCP');
    995=@('POP3S','E-mail seguro','TCP');
    1433=@('SQL Server','Banco de dados Microsoft SQL','TCP');
    1434=@('SQL Browser','Descoberta de instâncias SQL','UDP');
    1521=@('Oracle','Banco de dados Oracle','TCP');
    1701=@('L2TP','VPN L2TP','UDP');
    1723=@('PPTP','VPN PPTP (antiga, insegura)','TCP');
    1883=@('MQTT','Mensagens IoT sem criptografia','TCP');
    1900=@('SSDP/UPnP','Descoberta de dispositivos na rede','UDP');
    3306=@('MySQL','Banco de dados MySQL/MariaDB','TCP');
    3389=@('RDP','Área de trabalho remota Windows','TCP');
    4500=@('IPsec NAT-T','VPN IPsec através de NAT','UDP');
    5040=@('CDPSvc','Plataforma de dispositivos Windows','TCP');
    5353=@('mDNS','Descoberta local de nomes (Bonjour, Chromecast)','UDP');
    5355=@('LLMNR','Resolução de nomes local do Windows','UDP');
    5432=@('PostgreSQL','Banco de dados PostgreSQL','TCP');
    5900=@('VNC','Área de trabalho remota (VNC)','TCP');
    5985=@('WinRM HTTP','Administração remota via PowerShell','TCP');
    5986=@('WinRM HTTPS','Administração remota segura via PowerShell','TCP');
    6379=@('Redis','Cache/banco chave-valor','TCP');
    7680=@('Delivery Optimization','Distribuição de atualizações do Windows','TCP');
    8080=@('HTTP alternativo','Servidor web de desenvolvimento ou proxy','TCP');
    8443=@('HTTPS alternativo','Painéis e APIs web','TCP');
    8883=@('MQTT TLS','Mensagens IoT criptografadas','TCP');
    9200=@('Elasticsearch','Busca e índice de dados','TCP');
    11211=@('Memcached','Cache em memória','TCP');
    11434=@('Ollama API','Servidor local de modelos de IA','TCP');
    27017=@('MongoDB','Banco de dados MongoDB','TCP')
}

# process name (lowercase) => @(name, purpose)
$procKB = @{
    'system'=@('Kernel do Windows','Componente do sistema (SMB, NetBIOS, HTTP.sys)');
    'svchost'=@('Host de serviços do Windows','Agrupa vários serviços; veja o serviço exato com: tasklist /svc /fi "PID eq N"');
    'lsass'=@('Segurança e autenticação','Processo de segurança local do Windows');
    'services'=@('Gerenciador de serviços','Controla a inicialização de serviços');
    'wininit'=@('Inicialização do Windows','Processo de sessão do sistema');
    'spoolsv'=@('Spooler de impressão','Fila de impressão');
    'searchindexer'=@('Indexação do Windows','Pesquisa do Windows');
    'onedrive'=@('OneDrive','Sincronização de arquivos na nuvem Microsoft');
    'teams'=@('Microsoft Teams','Chat e chamadas');
    'ms-teams'=@('Microsoft Teams','Chat e chamadas');
    'chrome'=@('Google Chrome','Navegador web');
    'msedge'=@('Microsoft Edge','Navegador web');
    'firefox'=@('Firefox','Navegador web');
    'code'=@('VS Code','Editor de código');
    'cursor'=@('Cursor','Editor de código com IA');
    'ollama'=@('Ollama','Servidor local de modelos de IA');
    'ollama app'=@('Ollama (app)','Interface do Ollama');
    'pcloud'=@('pCloud','Sincronização de arquivos na nuvem');
    'spotify'=@('Spotify','Streaming de música');
    'spotifylauncher'=@('Spotify','Inicializador do Spotify');
    'eeventmanager'=@('Software de terceiros','Verifique fabricante e finalidade');
    'deepseek harness'=@('DeepSeek Harness','Aplicação de terceiros; confirme se foi instalada por você');
    'opencode'=@('OpenCode','Ferramenta de desenvolvimento com IA');
    'python'=@('Python','Interpretador ou script local');
    'node'=@('Node.js','Servidor ou ferramenta JavaScript');
    'php'=@('PHP','Servidor PHP (por exemplo, scan.php)');
    'java'=@('Java','Aplicação Java');
    'postgres'=@('PostgreSQL','Banco de dados');
    'mysqld'=@('MySQL','Banco de dados');
    'sqlservr'=@('SQL Server','Banco de dados Microsoft')
}

$riskNotes = @{
    21='Texto claro: senhas e dados trafegam sem criptografia. Desative se não usar.';
    23='Terminal em texto claro. Não deveria estar ativo.';
    135='RPC do Windows. Mantenha bloqueado para redes não confiáveis.';
    139='NetBIOS legado. Restrinja a redes confiáveis.';
    445='Compartilhamento SMB. Alvo frequente de worms e ransomware se exposto.';
    3389='Área de trabalho remota. Exponha apenas por VPN ou com MFA.';
    5900='VNC. Confirme que há senha e acesso restrito.';
    1433='Banco de dados. Não deve ser acessível de redes não confiáveis.';
    3306='Banco de dados. Não deve ser acessível de redes não confiáveis.';
    5432='Banco de dados. Não deve ser acessível de redes não confiáveis.';
    1521='Banco de dados. Não deve ser acessível de redes não confiáveis.';
    11434='API de IA local. Exposta na rede, qualquer host pode usar o modelo.'
}

function Get-PortInfo([int]$port) {
    if ($portKB.ContainsKey($port)) { return @{ Service = $portKB[$port][0]; Use = $portKB[$port][1] } }
    if ($port -ge 49152) { return @{ Service = 'Porta dinâmica'; Use = 'Porta temporária usada por apps e sistema em conexões de saída' } }
    return @{ Service = 'Desconhecido'; Use = 'Sem serviço padrão conhecido; identifique pelo processo' }
}

function Get-Purpose([string]$name, [string]$path) {
    $k = $name.ToLower()
    if ($procKB.ContainsKey($k)) { return $procKB[$k][0] + ': ' + $procKB[$k][1] }
    if (-not $path -or $path -eq 'Indisponível') { return 'Caminho indisponível. Execute como administrador para identificar.' }
    if ($path -like "$($env:SystemRoot)*") { return 'Componente do Windows (pasta do sistema).' }
    if ($path -like '*\Program Files*') { return 'Software instalado (Program Files). Confira o fabricante.' }
    if ($path -like "$($env:LOCALAPPDATA)*" -or $path -like "$($env:APPDATA)*") { return 'Aplicativo do usuário (AppData). Confirme se foi instalado por você.' }
    return 'Executável fora de pastas padrão: verifique a origem.'
}

# ---------------- Process lookup (cached) ----------------
$procCache = @{}
$cimCache = @{}
try { foreach ($cp in (Get-CimInstance Win32_Process -ErrorAction Stop)) { $cimCache[[int]$cp.ProcessId] = $cp } } catch {}
function Get-ProcInfo([int]$procId) {
    if ($procCache.ContainsKey($procId)) { return $procCache[$procId] }
    $name = 'Indisponível'; $path = 'Indisponível'; $started = ''
    if ($procId -eq 0) { $name = 'Ocioso do sistema'; $path = '(kernel)' }
    else {
        try {
            $p = Get-Process -Id $procId -ErrorAction Stop
            $name = $p.ProcessName
            try { $path = [string]$p.Path } catch {}
            try { $started = $p.StartTime.ToString('yyyy-MM-dd HH:mm') } catch {}
        } catch {}
        if (-not $path) { $path = '(kernel ou sem caminho)' }
    }
    $cmd = ''
    if ($cimCache.ContainsKey($procId)) { $cmd = [string]$cimCache[$procId].CommandLine }
    $info = [pscustomobject]@{ Name = $name; Path = $path; Cmd = $cmd; Started = $started; Purpose = (Get-Purpose $name $path) }
    $procCache[$procId] = $info
    return $info
}

# ---------------- Sockets: listeners and connections ----------------
$rawListeners = @()
foreach ($t in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
    $rawListeners += [pscustomobject]@{ Proto = 'TCP'; Addr = [string]$t.LocalAddress; Port = [int]$t.LocalPort; Owner = [int]$t.OwningProcess }
}
foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
    $rawListeners += [pscustomobject]@{ Proto = 'UDP'; Addr = [string]$u.LocalAddress; Port = [int]$u.LocalPort; Owner = [int]$u.OwningProcess }
}
$tcpAll = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Listen' })
$listenPorts = @{}; foreach ($x in $rawListeners) { $listenPorts[[int]$x.Port] = 1 }
$estByPid = @{}
foreach ($cn in $tcpAll) { $k = [int]$cn.OwningProcess; $estByPid[$k] = 1 + [int]$estByPid[$k] }

$listenRows = @(foreach ($x in $rawListeners) {
    $pi = Get-ProcInfo $x.Owner
    $pinfo = Get-PortInfo $x.Port
    $scope = if ($x.Addr -in @('127.0.0.1','::1')) { 'Localhost only' } elseif ($x.Addr -in @('0.0.0.0','::')) { 'All interfaces' } else { 'Specific interface' }
    $risk = 'Low'
    if ($scope -ne 'Localhost only') { $risk = 'Medium' }
    if ($scope -ne 'Localhost only' -and $riskNotes.ContainsKey($x.Port)) { $risk = 'High' }
    [pscustomobject]@{
        Proto = $x.Proto; Port = $x.Port; Service = $pinfo.Service; Use = $pinfo.Use
        Address = $x.Addr; Family = $(if ($x.Addr -match ':') {'IPv6'} else {'IPv4'})
        Scope = $scope; Risk = $risk
        Note = $(if ($riskNotes.ContainsKey($x.Port)) { $riskNotes[$x.Port] } else { '' })
        Pid = $x.Owner; Process = $pi.Name; Purpose = $pi.Purpose; Path = $pi.Path; Cmd = $pi.Cmd; Started = $pi.Started
        Established = [int]$estByPid[$x.Owner]
    }
})

$connRows = @(foreach ($cn in $tcpAll) {
    $pi = Get-ProcInfo ([int]$cn.OwningProcess)
    $rp = [int]$cn.RemotePort; $lp = [int]$cn.LocalPort
    $dir = if ($listenPorts.ContainsKey($lp)) { 'Entrada (atende uma porta local)' }
           elseif ($portKB.ContainsKey($rp)) { 'Saída para serviço conhecido' }
           else { 'Saída (porta alta ou desconhecida)' }
    $info = Get-PortInfo $rp
    [pscustomobject]@{
        Proto = 'TCP'; Local = [string]$cn.LocalAddress; LPort = $lp
        Remote = [string]$cn.RemoteAddress; RPort = $rp; State = [string]$cn.State
        Pid = [int]$cn.OwningProcess; Process = $pi.Name; Direction = $dir
        Service = $info.Service; Use = $info.Use; Purpose = $pi.Purpose; Path = $pi.Path; Cmd = $pi.Cmd
        Loopback = $(if ([string]$cn.RemoteAddress -in @('127.0.0.1','::1')) {'Sim'} else {'Não'})
    }
})

$procIds = @(@($listenRows | ForEach-Object { $_.Pid }) + @($connRows | ForEach-Object { $_.Pid }) | Sort-Object -Unique)
$procRows = @(foreach ($id in $procIds) {
    $pi = Get-ProcInfo $id
    $ls = @($listenRows | Where-Object { $_.Pid -eq $id })
    $cs = @($connRows | Where-Object { $_.Pid -eq $id })
    [pscustomobject]@{
        Pid = $id; Process = $pi.Name; Purpose = $pi.Purpose; Path = $pi.Path; Cmd = $pi.Cmd
        Listeners = $ls.Count; Connections = $cs.Count
        Ports = (($ls | ForEach-Object { "$($_.Proto)/$($_.Port)" }) | Sort-Object -Unique) -join ', '
        Remote = (($cs | ForEach-Object { "$($_.Remote):$($_.RPort)" }) | Select-Object -First 5) -join ', '
    }
})

$topServices = @($connRows | Group-Object RPort | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
    $info = Get-PortInfo ([int]$_.Name)
    [pscustomobject]@{ Port = [int]$_.Name; Count = $_.Count; Service = $info.Service; Use = $info.Use }
})

# ---------------- Network configuration (read-only) ----------------
function Run-Cmd([string]$exe, [string[]]$cmdArgs) {
    try { (& $exe @cmdArgs 2>&1 | Out-String).Trim() } catch { "Erro: $($_.Exception.Message)" }
}
$ipconfigText = Run-Cmd 'ipconfig' @('/all')
$routeText = Run-Cmd 'route' @('print')
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
try { $hostsText = (Get-Content -Path $hostsPath -Raw -ErrorAction Stop) } catch { $hostsText = "Erro ao ler ${hostsPath}: $($_.Exception.Message)" }
$hostsActive = @(); if ($hostsText) { $hostsActive = @($hostsText -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' }) }

$adapters = @(); try { $adapters = @(Get-NetAdapter -ErrorAction Stop | Sort-Object ifIndex | ForEach-Object { [pscustomobject]@{ Interface = $_.Name; Description = $_.InterfaceDescription; MAC = $_.MacAddress; Status = [string]$_.Status; Speed = $_.LinkSpeed; IfIndex = $_.ifIndex } }) } catch {}
$ipAddrs = @(); try { $ipAddrs = @(Get-NetIPAddress -ErrorAction Stop | Sort-Object InterfaceIndex | ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; Family = [string]$_.AddressFamily; IP = $_.IPAddress; Prefix = $_.PrefixLength; Origin = [string]$_.PrefixOrigin; IfIndex = $_.InterfaceIndex } }) } catch {}
$neighbors = @(); try { $neighbors = @(Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.LinkLayerAddress -and $_.State -notin @('Unreachable','Incomplete') } | ForEach-Object { [pscustomobject]@{ IP = $_.IPAddress; MAC = $_.LinkLayerAddress; State = [string]$_.State; IfIndex = $_.InterfaceIndex } }) } catch {}
$netRoutes = @(); try { $netRoutes = @(Get-NetRoute -ErrorAction Stop | Sort-Object RouteMetric | ForEach-Object { [pscustomobject]@{ Destination = $_.DestinationPrefix; NextHop = $_.NextHop; Metric = $_.RouteMetric; Interface = $_.InterfaceAlias; Protocol = [string]$_.Protocol; Store = [string]$_.Store } }) } catch {}
$dns = @(); try { $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.ServerAddresses } | ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; Servers = (@($_.ServerAddresses) -join ', ') } }) } catch {}

$defaultRoutes = @($netRoutes | Where-Object { $_.Destination -eq '0.0.0.0/0' } | Sort-Object Metric)
$primary = $defaultRoutes | Select-Object -First 1
$primaryIf = if ($primary) { $primary.Interface } else { '—' }
$gateway = if ($primary) { $primary.NextHop } else { '—' }
$primaryIp = (@($ipAddrs | Where-Object { $_.Interface -eq $primaryIf -and $_.Family -eq 'IPv4' } | ForEach-Object { $_.IP }) | Select-Object -First 1)

# ---------------- Firewall (read-only) ----------------
$fwProfiles = @(); try { $fwProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Profile = [string]$_.Name; Enabled = [string]$_.Enabled; DefaultInbound = [string]$_.DefaultInboundAction; DefaultOutbound = [string]$_.DefaultOutboundAction; LogBlocked = [string]$_.LogBlocked; LogFile = [string]$_.LogFileName } }) } catch {}
$fwRules = @(); $fwBlockCount = 0
try {
    $pfIdx = @{}; foreach ($x in (Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) { $pfIdx[$x.InstanceID] = $x }
    $afIdx = @{}; foreach ($x in (Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue)) { $afIdx[$x.InstanceID] = $x }
    $adIdx = @{}; foreach ($x in (Get-NetFirewallAddressFilter -All -ErrorAction SilentlyContinue)) { $adIdx[$x.InstanceID] = $x }
    $listenList = @($listenRows | ForEach-Object { $_.Port })
    $fwBlockCount = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Block -ErrorAction SilentlyContinue).Count
    $fwRules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop | ForEach-Object {
        $pf = $pfIdx[$_.Name]; $af = $afIdx[$_.Name]; $ad = $adIdx[$_.Name]
        $localPort = if ($pf -and $pf.LocalPort) { (@($pf.LocalPort) -join ',') } else { 'Qualquer' }
        $protocol  = if ($pf -and $pf.Protocol) { [string]$pf.Protocol } else { 'Qualquer' }
        $program   = if ($af -and $af.Program -and $af.Program -ne 'Any') { [string]$af.Program } else { 'Qualquer' }
        $remote    = if ($ad -and $ad.RemoteAddress) { (@($ad.RemoteAddress) -join ',') } else { 'Qualquer' }
        $portNums  = @($localPort -split ',' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
        $matches   = @($portNums | Where-Object { $listenList -contains $_ }).Count -gt 0
        $broad     = ($localPort -eq 'Qualquer' -and $program -eq 'Qualquer')
        [pscustomobject]@{
            Name = [string]$_.DisplayName; Profile = [string]$_.Profile; Protocol = $protocol
            LocalPort = $localPort; Remote = $remote; Program = $program
            Matches = $(if ($matches) {'Yes'} else {'No'}); Broad = $(if ($broad) {'Yes'} else {'No'})
        }
    } | Sort-Object @{Expression={$_.Broad};Descending=$true}, @{Expression={$_.Matches};Descending=$true}, Name)
} catch {}
$fwBroad = @($fwRules | Where-Object { $_.Broad -eq 'Yes' }).Count
$fwMatch = @($fwRules | Where-Object { $_.Matches -eq 'Yes' }).Count

# ---------------- Optional traffic capture (needs administrator) ----------------
$capture = [ordered]@{ Requested = $CaptureSeconds; Status = 'Não solicitada'; Note = ''; Files = @() }
if ($CaptureSeconds -gt 0) {
    if (-not $isAdmin) {
        $capture.Status = 'Ignorada'
        $capture.Note = 'A captura exige PowerShell como administrador. Abra o PowerShell como administrador e rode: .\local-scanner.ps1 -CaptureSeconds 30'
    } else {
        $etl = Join-Path $PSScriptRoot "capture-$stamp.etl"
        $pcap = Join-Path $PSScriptRoot "capture-$stamp.pcapng"
        try {
            pktmon filter remove | Out-Null
            pktmon start --capture --comp nics --pkt-size 128 -f $etl | Out-Null
            Start-Sleep -Seconds $CaptureSeconds
            pktmon stop | Out-Null
            pktmon etl2pcap $etl -o $pcap | Out-Null
            $capture.Status = 'Concluída'
            $capture.Files = @($etl, $pcap)
            $capture.Note = "Cabeçalhos dos pacotes ($CaptureSeconds s, 128 bytes por pacote). Abra o .pcapng no Wireshark."
        } catch {
            $capture.Status = 'Erro'
            $capture.Note = $_.Exception.Message
        }
    }
}

# ---------------- Findings ----------------
$findings = New-Object System.Collections.ArrayList
function Add-Finding([string]$level, [string]$title, [string]$detail) {
    [void]$findings.Add([pscustomobject]@{ Level = $level; Title = $title; Detail = $detail })
}
foreach ($x in @($listenRows | Where-Object { $_.Risk -eq 'High' })) {
    Add-Finding 'high' "Serviço de risco exposto: $($x.Proto)/$($x.Port) ($($x.Service))" "Escuta em $($x.Address) ($($x.Scope)). Processo: $($x.Process) (PID $($x.Pid)). $($x.Note)"
}
foreach ($p in @($fwProfiles | Where-Object { $_.Enabled -ne 'True' })) {
    Add-Finding 'high' "Firewall desativado no perfil $($p.Profile)" 'Sem firewall, serviços podem ficar acessíveis na rede.'
}
foreach ($p in @($fwProfiles | Where-Object { $_.DefaultInbound -eq 'Allow' })) {
    Add-Finding 'high' "Entrada padrão 'Permitir' no perfil $($p.Profile)" 'Conexões de entrada não cobertas por regra são aceitas.'
}
if ($fwBroad -gt 0) {
    Add-Finding 'medium' "$fwBroad regras de entrada amplas" 'Regras permitem qualquer porta e qualquer programa. Revise a aba Firewall.'
}
$appDataProcs = @($procRows | Where-Object { $_.Path -like "$($env:APPDATA)*" -or $_.Path -like "$($env:LOCALAPPDATA)*" } | ForEach-Object { $_.Process } | Sort-Object -Unique)
if ($appDataProcs.Count -gt 0) {
    Add-Finding 'medium' 'Processos executados a partir de AppData' ("Confirme se você instalou: " + ($appDataProcs -join ', '))
}
$exposedCount = @($listenRows | Where-Object { $_.Scope -ne 'Localhost only' }).Count
Add-Finding 'info' "$exposedCount portas acessíveis fora do localhost" 'Ver aba Portas, filtro Escopo.'
if ($hostsActive.Count -gt 0) {
    Add-Finding 'info' "Arquivo hosts com $($hostsActive.Count) entradas ativas" 'Verifique se não há redirecionamentos inesperados (aba Hosts).'
}
if (-not $isAdmin) {
    Add-Finding 'info' 'Execução sem administrador' 'Alguns caminhos de processo e regras podem estar indisponíveis. Execute como administrador para ver mais.'
}

# ---------------- Summary ----------------
$summary = [ordered]@{
    Computer = $env:COMPUTERNAME; User = $env:USERNAME; Generated = $generated.ToString('yyyy-MM-dd HH:mm:ss'); IsAdmin = $isAdmin
    Listeners = $listenRows.Count
    ListenTcp = @($listenRows | Where-Object { $_.Proto -eq 'TCP' }).Count
    ListenUdp = @($listenRows | Where-Object { $_.Proto -eq 'UDP' }).Count
    Exposed = $exposedCount
    HighRisk = @($listenRows | Where-Object { $_.Risk -eq 'High' }).Count
    Connections = $connRows.Count
    Established = @($connRows | Where-Object { $_.State -eq 'Established' }).Count
    RemoteHosts = @($connRows | Where-Object { $_.Remote -notin @('0.0.0.0','::','127.0.0.1','::1') } | Select-Object -ExpandProperty Remote -Unique).Count
    Processes = $procRows.Count
    AdaptersUp = @($adapters | Where-Object { $_.Status -eq 'Up' }).Count
    Neighbors = $neighbors.Count
    PrimaryInterface = $primaryIf; PrimaryIp = $primaryIp; Gateway = $gateway
    Dns = (@($dns | ForEach-Object { $_.Servers }) -join ' | ')
    FwRulesAllow = $fwRules.Count; FwBroad = $fwBroad; FwMatch = $fwMatch
    HostsActive = $hostsActive.Count
}

$data = [ordered]@{
    summary = $summary
    findings = @($findings)
    listeners = @($listenRows)
    connections = @($connRows)
    processes = @($procRows)
    topServices = @($topServices)
    network = [ordered]@{ adapters = @($adapters); ips = @($ipAddrs); neighbors = @($neighbors); routes = @($netRoutes); dns = @($dns); ipconfig = $ipconfigText; routeRaw = $routeText }
    hosts = [ordered]@{ path = $hostsPath; active = $hostsActive.Count; text = [string]$hostsText }
    firewall = [ordered]@{ profiles = @($fwProfiles); rules = @($fwRules); blockRules = $fwBlockCount }
    capture = $capture
}
$json = (ConvertTo-Json -InputObject $data -Depth 8 -Compress).Replace('</', '<\/')

# ---------------- Console summary ----------------
Write-Host ''
Write-Host 'LOCAL NETWORK INSPECTOR' -ForegroundColor Cyan
Write-Host ("Computador: $env:COMPUTERNAME   Admin: $isAdmin   Gerado: $generated")
Write-Host ("Portas em escuta: $($summary.Listeners) (TCP $($summary.ListenTcp), UDP $($summary.ListenUdp))   Acessíveis fora do localhost: $exposedCount   Alto risco: $($summary.HighRisk)")
Write-Host ("Conexões: $($connRows.Count) (estabelecidas $($summary.Established))   Hosts remotos: $($summary.RemoteHosts)   Processos: $($procRows.Count)")
Write-Host ("Rede principal: $primaryIf  IP $primaryIp  Gateway $gateway")
Write-Host ("Firewall: regras de entrada permitidas $($fwRules.Count) (amplas: $fwBroad)")
if ($CaptureSeconds -gt 0) { Write-Host ("Captura: " + $capture.Status + ' - ' + $capture.Note) -ForegroundColor Yellow }
Write-Host ''

# ---------------- Interactive HTML report (template + data) ----------------
$template = @'
<!doctype html>
<html lang="pt-BR" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>Inspetor de rede local</title>
<style>
/* Preto e branco com tons neutros. Cores de status são usadas só para sinalizar risco. */
:root{
  --bg:#000;--panel:#0b0b0b;--card:#111;--card2:#171717;--line:#262626;--line2:#333;
  --text:#f2f2f2;--muted:#8c8c8c;--strong:#fff;--accent:#fff;--accentText:#000;
  --code:#060606;--codetext:#d4d4d4;--hover:#1a1a1a;
  --ok:#86efac;--warn:#fcd34d;--bad:#fca5a5;
  --ok-bg:rgba(134,239,172,.10);--warn-bg:rgba(252,211,77,.10);--bad-bg:rgba(252,165,165,.12);--info-bg:rgba(255,255,255,.06);
  --radius:12px;--shadow:0 1px 0 rgba(255,255,255,.04) inset;
}
:root[data-theme="light"]{
  --bg:#fff;--panel:#fafafa;--card:#fff;--card2:#f4f4f4;--line:#e5e5e5;--line2:#d4d4d4;
  --text:#111;--muted:#6b6b6b;--strong:#000;--accent:#111;--accentText:#fff;
  --code:#f5f5f5;--codetext:#111;--hover:#f2f2f2;
  --ok:#166534;--warn:#92400e;--bad:#991b1b;
  --ok-bg:#dcfce7;--warn-bg:#fef3c7;--bad-bg:#fee2e2;--info-bg:#f0f0f0;
  --shadow:none;
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.app{display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh}
aside{background:var(--panel);border-right:1px solid var(--line);padding:22px 14px;position:sticky;top:0;height:100vh;overflow:auto;display:flex;flex-direction:column;gap:18px}
.brand{display:flex;gap:10px;align-items:center;padding:0 6px}
.mark{width:32px;height:32px;border-radius:9px;background:var(--accent);color:var(--accentText);display:grid;place-items:center;font-weight:800;font-size:15px}
.brand b{display:block;font-size:15px;color:var(--strong)}.brand small{color:var(--muted);font-size:12px}
.nav{display:flex;flex-direction:column;gap:2px}
.nav button{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;text-align:left;background:none;border:0;border-radius:9px;padding:9px 11px;color:var(--muted);cursor:pointer;font:inherit;transition:background .15s,color .15s}
.nav button:hover{background:var(--hover);color:var(--text)}
.nav button[aria-current="page"]{background:var(--accent);color:var(--accentText);font-weight:600}
.nav .n{font-size:11px;opacity:.75;font-variant-numeric:tabular-nums}
.side-foot{margin-top:auto;color:var(--muted);font-size:12px;padding:0 6px}
main{padding:0 28px 40px;min-width:0}
.top{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border-bottom:1px solid var(--line);margin:0 -28px 22px;padding:16px 28px;display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between}
.top h2{font-size:20px;margin:0;color:var(--strong);letter-spacing:-.01em}
.top .meta{color:var(--muted);font-size:12px;margin-top:2px}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.btn{border:1px solid var(--line2);background:var(--card);color:var(--text);border-radius:9px;padding:7px 12px;cursor:pointer;font:inherit;font-weight:600;font-size:13px;transition:border-color .15s,background .15s}
.btn:hover{border-color:var(--text)}
.btn.solid{background:var(--accent);color:var(--accentText);border-color:var(--accent)}
.btn:focus-visible,select:focus-visible,input:focus-visible,summary:focus-visible,tr.row:focus-visible{outline:2px solid var(--text);outline-offset:2px}
h3{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:26px 0 10px;font-weight:700}
.muted{color:var(--muted)}
.hero{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:14px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);min-width:0}
.card h4{margin:0 0 12px;font-size:14px;color:var(--strong);display:flex;justify-content:space-between;align-items:center;gap:8px}
.card .sub{color:var(--muted);font-size:12px;margin:-6px 0 12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px;cursor:pointer;text-align:left;color:var(--text);font:inherit;transition:border-color .15s,transform .15s}
.stat:hover{border-color:var(--text);transform:translateY(-1px)}
.stat .v{display:block;font-size:28px;font-weight:700;color:var(--strong);font-variant-numeric:tabular-nums;line-height:1.1}
.stat .l{display:block;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em;margin-top:6px}
.stat .d{display:block;color:var(--muted);font-size:12px}
.two{display:grid;gap:14px;grid-template-columns:1fr 1fr}
.findings{display:flex;flex-direction:column;gap:8px}
.f{display:grid;grid-template-columns:auto 1fr;gap:10px;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:var(--info-bg)}
.f .tag{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;padding:3px 8px;border-radius:999px;height:fit-content;white-space:nowrap}
.f.high{background:var(--bad-bg);border-color:transparent}.f.high .tag{background:var(--bad);color:var(--bg)}
.f.medium{background:var(--warn-bg);border-color:transparent}.f.medium .tag{background:var(--warn);color:var(--bg)}
.f.info .tag{background:var(--line2);color:var(--text)}
.f strong{display:block;color:var(--strong);font-weight:600}.f span.d{color:var(--muted);font-size:12.5px}
.empty{color:var(--muted);font-style:italic;padding:8px 0}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;align-items:center}
.search{position:relative;flex:1;min-width:220px}
.search input{width:100%;padding:9px 12px 9px 34px;border:1px solid var(--line2);border-radius:9px;background:var(--card);color:var(--text);font:inherit}
.search::before{content:"";position:absolute;left:12px;top:50%;width:12px;height:12px;margin-top:-8px;border:2px solid var(--muted);border-radius:50%}
.search::after{content:"";position:absolute;left:23px;top:50%;width:6px;height:2px;background:var(--muted);transform:rotate(45deg);transform-origin:left;margin-top:5px}
select{padding:9px 10px;border:1px solid var(--line2);border-radius:9px;background:var(--card);color:var(--text);font:inherit;cursor:pointer}
.count{color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums;white-space:nowrap}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:var(--radius);background:var(--card)}
table{width:100%;border-collapse:separate;border-spacing:0}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{position:sticky;top:0;background:var(--card2);font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;font-weight:700;z-index:1}
tbody tr:last-child td{border-bottom:0}
tr.row{cursor:pointer;transition:background .12s}
tr.row:hover td{background:var(--hover)}
tr.row td:first-child{position:relative}
tr.row.open td{background:var(--hover)}
tr.row td:first-child::before{content:"›";position:absolute;left:4px;top:9px;color:var(--muted);transition:transform .15s;font-size:14px}
tr.row.open td:first-child::before{transform:rotate(90deg)}
tr.row td:first-child{padding-left:20px}
td.num,th.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px}
.detail td{background:var(--panel);padding:16px 18px 18px 20px}
.kv{display:grid;grid-template-columns:minmax(160px,230px) minmax(0,1fr);gap:8px 18px;margin:0}
.kv dt{color:var(--muted);font-size:12px;font-weight:600;padding-top:1px}
.kv dd{margin:0;word-break:break-word;color:var(--text)}
.pill{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;border:1px solid transparent}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.p-local{background:var(--info-bg);color:var(--text);border-color:var(--line2)}
.p-exposed{background:var(--warn-bg);color:var(--warn)}
.p-low{background:var(--ok-bg);color:var(--ok)}
.p-med{background:var(--warn-bg);color:var(--warn)}
.p-high{background:var(--bad-bg);color:var(--bad)}
.p-open{background:var(--info-bg);color:var(--text);border-color:var(--line2)}
.p-none{background:transparent;color:var(--muted);border-color:var(--line)}
.tip{background:var(--card);border:1px dashed var(--line2);border-radius:10px;padding:10px 14px;color:var(--muted);font-size:13px;margin-bottom:14px}
.tip b{color:var(--text)}
.code{position:relative;background:var(--code);color:var(--codetext);padding:14px 16px;border-radius:10px;border:1px solid var(--line);font:12px/1.55 Consolas,"Cascadia Mono",monospace;overflow:auto;white-space:pre;margin:0;max-height:520px}
.hl{background:var(--info-bg);color:var(--strong);display:block;border-left:2px solid var(--text);padding-left:8px;margin-left:-10px}
details{margin-bottom:12px}
details>summary{cursor:pointer;color:var(--muted);font-size:13px;padding:6px 0;list-style:none;user-select:none}
details>summary::before{content:"+ ";font-family:Consolas,monospace}
details[open]>summary::before{content:"− "}
details>summary:hover{color:var(--text)}
.copy{position:absolute;top:8px;right:8px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-size:12px;border:1px solid var(--line2);border-radius:999px;padding:3px 10px;color:var(--text)}
.cols-3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.profile h4 .st{font-size:11px;text-transform:uppercase;letter-spacing:.05em}
ul.plain{margin:0;padding-left:18px}
ul.plain li{margin:4px 0}
kbd{font:12px Consolas,monospace;border:1px solid var(--line2);border-bottom-width:2px;border-radius:5px;padding:0 5px;color:var(--text);background:var(--card)}
.overlay-hint{color:var(--muted);font-size:12px}
@media (max-width:1000px){.hero,.two{grid-template-columns:1fr}.cols-3{grid-template-columns:1fr 1fr}}
@media (max-width:820px){
  .app{grid-template-columns:1fr}
  aside{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line);padding:14px}
  .nav{flex-direction:row;overflow-x:auto;gap:4px;padding-bottom:2px}
  .nav button{width:auto;white-space:nowrap}
  .side-foot{display:none}
  main{padding:0 16px 32px}
  .top{margin:0 -16px 18px;padding:12px 16px;position:static}
  .kv{grid-template-columns:1fr;gap:2px 0}
  .kv dd{margin-bottom:8px}
  .cols-3{grid-template-columns:1fr}
}
</style></head>
<body><div class="app">
<aside>
  <div class="brand"><div class="mark">◐</div><div><b>Inspetor de rede</b><small id="who"></small></div></div>
  <nav class="nav" id="nav" aria-label="Seções"></nav>
  <div class="side-foot">
    <div>Somente leitura</div>
    <div>Nada é enviado para fora</div>
  </div>
</aside>
<main>
  <header class="top">
    <div><h2 id="title">Resumo</h2><div class="meta" id="gen"></div></div>
    <div class="actions">
      <button class="btn" id="expandAll" title="Abrir todos os detalhes da seção">Expandir</button>
      <button class="btn" id="collapseAll" title="Fechar todos os detalhes">Recolher</button>
      <button class="btn" id="theme" title="Alternar tema claro/escuro" aria-label="Alternar tema">Tema</button>
      <button class="btn solid" id="print" title="Imprimir ou salvar como PDF">Imprimir</button>
    </div>
  </header>
  <section id="resumo" class="view"></section>
  <section id="portas" class="view" hidden></section>
  <section id="conexoes" class="view" hidden></section>
  <section id="processos" class="view" hidden></section>
  <section id="rede" class="view" hidden></section>
  <section id="hosts" class="view" hidden></section>
  <section id="firewall" class="view" hidden></section>
  <section id="captura" class="view" hidden></section>
</main></div>
<script>
const D = __DATA__;
const views = [];
const SECTIONS = [];
const el = (tag, attrs, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
};
const show = v => (v === undefined || v === null || v === '') ? '—' : v;
const uniq = (arr, k) => [...new Set(arr.map(x => String(x[k] ?? '')))].filter(Boolean).sort();
const kv = pairs => el('dl', { class: 'kv' }, pairs.map(([k, v]) => [el('dt', { text: k }), el('dd', { text: show(v) })]));
const pill = (text, cls) => el('span', { class: 'pill ' + cls, text });
const RISK = { High: ['Alto', 'p-high'], Medium: ['Médio', 'p-med'], Low: ['Baixo', 'p-low'] };
const SCOPE = { 'Localhost only': ['Só local', 'p-local'], 'All interfaces': ['Todas as interfaces', 'p-exposed'], 'Specific interface': ['Interface específica', 'p-exposed'] };
const card = (title, sub, ...kids) => el('div', { class: 'card' }, el('h4', null, title), sub ? el('div', { class: 'sub', text: sub }) : null, kids);
const note = (html) => { const d = el('div', { class: 'tip' }); d.innerHTML = html; return d; };
const copyBtn = (getText) => el('button', { class: 'btn copy', onclick: async (e) => {
  try { await navigator.clipboard.writeText(getText()); e.target.textContent = 'Copiado'; }
  catch { e.target.textContent = 'Falhou'; }
  setTimeout(() => e.target.textContent = 'Copiar', 1400);
} }, 'Copiar');
const codeBlock = (text) => { const pre = el('pre', { class: 'code', text }); return el('div', { style: 'position:relative' }, pre, copyBtn(() => text)); };

// Lista com busca, filtros, ordenação simples e detalhes expansíveis
function listView(host, { cols, rows, detail, filters = [], search = true, empty = 'Nada encontrado.' }) {
  const items = [];
  const q = el('input', { type: 'search', placeholder: 'Buscar em qualquer campo…', 'aria-label': 'Buscar', autocomplete: 'off' });
  const sels = filters.map(f => {
    const s = el('select', { 'aria-label': f.label }, el('option', { value: '', text: f.all }),
      f.options.map(o => { const [v, t] = Array.isArray(o) ? o : [o, o]; return el('option', { value: v, text: t }); }));
    s.addEventListener('change', () => apply());
    return s;
  });
  const count = el('span', { class: 'count' });
  const tbody = el('tbody');
  const table = el('table', null,
    el('thead', null, el('tr', null, cols.map(c => el('th', { class: c.num ? 'num' : '', text: c.label || c.k })))),
    tbody);
  for (const r of rows) {
    const tr = el('tr', { class: detail ? 'row' : '', tabindex: detail ? '0' : null }, cols.map(c => el('td', { class: c.num ? 'num' : '' }, c.render ? c.render(r) : show(r[c.k]))));
    const it = { tr, dr: null, open: false,
      text: cols.map(c => String(r[c.k] ?? '')).join(' ').toLowerCase() + ' ' + String(r._search ?? '').toLowerCase(),
      flt: Object.fromEntries(filters.map(f => [f.key, String(r[f.key] ?? '')])) };
    tbody.append(tr);
    if (detail) {
      const dr = el('tr', { class: 'detail' }, el('td', { colspan: cols.length }, detail(r)));
      dr.hidden = true; it.dr = dr; tbody.append(dr);
      const toggle = () => { it.open = !it.open; tr.classList.toggle('open', it.open); apply(); };
      tr.addEventListener('click', toggle);
      tr.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    }
    items.push(it);
  }
  const emptyRow = el('tr', { hidden: true }, el('td', { colspan: cols.length, class: 'empty', text: empty }));
  tbody.append(emptyRow);
  function apply() {
    const v = q.value.trim().toLowerCase();
    let n = 0;
    for (const it of items) {
      const ok = it.text.includes(v) && sels.every((s, i) => !s.value || it.flt[filters[i].key] === s.value);
      it.tr.hidden = !ok;
      if (it.dr) it.dr.hidden = !ok || !it.open;
      if (ok) n++;
    }
    emptyRow.hidden = n !== 0;
    count.textContent = `${n} de ${items.length}`;
  }
  q.addEventListener('input', apply);
  const view = { setAll(o) { items.forEach(it => { it.open = o; it.tr.classList.toggle('open', o); }); apply(); }, focus() { q.focus(); } };
  views.push(view);
  const bar = el('div', { class: 'toolbar' }, search ? el('div', { class: 'search' }, q) : null, sels, count);
  host.replaceChildren(bar, el('div', { class: 'table-wrap' }, table));
  apply();
  return view;
}

// ---- Resumo ----
function renderSummary(host) {
  const s = D.summary;
  const stats = [
    ['portas', 'Portas em escuta', s.Listeners, `TCP ${s.ListenTcp} · UDP ${s.ListenUdp}`],
    ['portas', 'Acessíveis pela rede', s.Exposed, 'Fora do localhost'],
    ['conexoes', 'Conexões', s.Established, `${s.Connections} sockets TCP · ${s.Established} estabelecidas`],
    ['conexoes', 'Hosts remotos', s.RemoteHosts, 'IPs distintos'],
    ['processos', 'Processos', s.Processes, 'com portas ou conexões'],
    ['firewall', 'Regras permitidas', s.FwRulesAllow, `${s.FwBroad} amplas`],
  ];
  const sevLabel = { high: 'Alto', medium: 'Médio', info: 'Info' };
  const findingsBox = D.findings.length
    ? el('div', { class: 'findings' }, D.findings.map(f => el('div', { class: 'f ' + f.Level },
        el('span', { class: 'tag', text: sevLabel[f.Level] }),
        el('div', null, el('strong', { text: f.Title }), el('span', { class: 'd', text: f.Detail })))))
    : el('div', { class: 'empty', text: 'Nenhum achado.' });
  const topProcs = [...D.processes].sort((a, b) => (b.Listeners + b.Connections) - (a.Listeners + a.Connections)).slice(0, 8);

  host.replaceChildren(
    el('div', { class: 'stats' }, stats.map(([id, label, n, sub]) =>
      el('button', { class: 'stat', onclick: () => go(id) },
        el('span', { class: 'v', text: n }), el('span', { class: 'l', text: label }), el('span', { class: 'd', text: sub })))),
    el('div', { class: 'hero' },
      card('Achados', `${D.findings.length} itens, do mais grave ao informativo`, findingsBox),
      card('Rede principal', 'Como este computador está conectado',
        kv([
          ['Interface', s.PrimaryInterface], ['Endereço IP', s.PrimaryIp], ['Gateway', s.Gateway],
          ['DNS', s.Dns], ['Adaptadores ativos', s.AdaptersUp], ['Vizinhos (ARP)', s.Neighbors],
        ]))),
    el('div', { class: 'two' },
      card('Processos mais ativos', 'Finalidade estimada pelo nome e caminho do executável',
        el('div', { id: 'sumProcs' })),
      card('Serviços mais usados agora', 'Conexões de saída, por porta remota (estimativa)',
        el('div', { id: 'sumSvc' }))),
    el('div', { class: 'tip', style: 'margin-top:14px' },
      el('b', { text: 'Dica: ' }), 'use as seções do menu para explorar cada parte. Clique em uma linha para ver detalhes. Pressione ',
      el('kbd', { text: '/' }), ' para buscar em qualquer seção.'),
  );
  listView(document.getElementById('sumProcs'), {
    search: false,
    cols: [{ k: 'Process', label: 'Processo' }, { k: 'Purpose', label: 'Finalidade (estimada)' },
           { k: 'Listeners', label: 'Portas', num: true }, { k: 'Connections', label: 'Conexões', num: true }],
    rows: topProcs,
    detail: p => kv([['PID', p.Pid], ['Caminho', p.Path], ['Portas', p.Ports], ['Remotos', p.Remote]]),
  });
  listView(document.getElementById('sumSvc'), {
    search: false,
    cols: [{ k: 'Port', label: 'Porta', num: true }, { k: 'Service', label: 'Serviço' }, { k: 'Use', label: 'Uso provável' }, { k: 'Count', label: 'Conexões', num: true }],
    rows: D.topServices,
  });
}

// ---- Portas ----
function renderPorts(host) {
  host.append(note('<b>Portas em escuta</b> são serviços que aceitam conexões neste computador. O <b>uso provável</b> é uma estimativa pela porta; o processo mostra quem a abriu.'));
  const box = el('div'); host.append(box);
  listView(box, {
    cols: [
      { k: 'Proto', label: 'Protocolo' }, { k: 'Port', label: 'Porta', num: true }, { k: 'Service', label: 'Serviço' },
      { k: 'Use', label: 'Uso provável (estimado)' },
      { k: 'Scope', label: 'Escopo', render: r => pill(SCOPE[r.Scope][0], SCOPE[r.Scope][1]) },
      { k: 'Risk', label: 'Risco', render: r => pill(RISK[r.Risk][0], RISK[r.Risk][1]) },
      { k: 'Process', label: 'Processo' },
    ],
    rows: D.listeners.map(l => ({ ...l, _search: `${l.Process} ${l.Purpose} ${l.Address}` })),
    filters: [
      { key: 'Proto', label: 'Protocolo', all: 'Todos os protocolos', options: ['TCP', 'UDP'] },
      { key: 'Scope', label: 'Escopo', all: 'Todos os escopos', options: [['Localhost only', 'Só local'], ['All interfaces', 'Todas as interfaces'], ['Specific interface', 'Interface específica']] },
      { key: 'Risk', label: 'Risco', all: 'Todos os riscos', options: [['High', 'Alto'], ['Medium', 'Médio'], ['Low', 'Baixo']] },
    ],
    detail: l => el('div', null,
      kv([
        ['Endereço de escuta', `${l.Address} (${l.Family})`], ['Escopo', SCOPE[l.Scope][0]],
        ['Serviço provável', l.Service], ['Uso provável (estimativa)', l.Use],
        ['Risco', RISK[l.Risk][0]], ['Observação de risco', l.Note],
        ['Processo', `${l.Process} (PID ${l.Pid})`], ['Finalidade do processo (estimada)', l.Purpose],
        ['Caminho', l.Path], ['Linha de comando', l.Cmd], ['Conexões estabelecidas', l.Established], ['Iniciado em', l.Started],
      ])),
  });
}

// ---- Conexões ----
function renderConnections(host) {
  host.append(note('<b>Conexões TCP</b> ativas e em transição. Em conexões de saída, o <b>serviço remoto</b> vem da porta do outro lado: 443 costuma ser HTTPS.'));
  const box = el('div'); host.append(box);
  listView(box, {
    cols: [
      { k: 'Local', label: 'Local', render: c => el('span', { class: 'mono', text: `${c.Local}:${c.LPort}` }) },
      { k: 'Remote', label: 'Remoto', render: c => el('span', { class: 'mono', text: `${c.Remote}:${c.RPort}` }) },
      { k: 'State', label: 'Estado' },
      { k: 'Process', label: 'Processo' },
      { k: 'Direction', label: 'Direção' },
      { k: 'Service', label: 'Serviço remoto (estimado)' },
    ],
    rows: D.connections.map(c => ({ ...c, _search: `${c.Remote} ${c.RPort} ${c.Process} ${c.Service}` })),
    filters: [
      { key: 'State', label: 'Estado', all: 'Todos os estados', options: uniq(D.connections, 'State') },
      { key: 'Direction', label: 'Direção', all: 'Todas as direções', options: uniq(D.connections, 'Direction') },
    ],
    empty: 'Nenhuma conexão encontrada.',
    detail: c => kv([
      ['Remoto', `${c.Remote}:${c.RPort}`], ['Local', `${c.Local}:${c.LPort}`], ['Estado', c.State],
      ['Direção', c.Direction], ['Serviço remoto (estimado)', c.Service], ['Uso provável (estimativa)', c.Use],
      ['Processo', `${c.Process} (PID ${c.Pid})`], ['Finalidade do processo (estimada)', c.Purpose],
      ['Caminho', c.Path], ['Linha de comando', c.Cmd], ['Loopback', c.Loopback],
    ]),
  });
}

// ---- Processos ----
function renderProcesses(host) {
  host.append(note('<b>Processos</b> com portas abertas ou conexões. A finalidade é estimada pelo nome e pelo caminho do executável.'));
  const box = el('div'); host.append(box);
  listView(box, {
    cols: [
      { k: 'Pid', label: 'PID', num: true }, { k: 'Process', label: 'Processo' }, { k: 'Purpose', label: 'Finalidade (estimada)' },
      { k: 'Listeners', label: 'Portas', num: true }, { k: 'Connections', label: 'Conexões', num: true }, { k: 'Ports', label: 'Portas abertas' },
    ],
    rows: D.processes.map(p => ({ ...p, _search: `${p.Path} ${p.Ports} ${p.Remote}` })),
    detail: p => kv([['Caminho', p.Path], ['Linha de comando', p.Cmd], ['Portas', p.Ports], ['Remotos recentes', p.Remote]]),
  });
}

// ---- Rede ----
function renderNetwork(host) {
  const n = D.network;
  host.replaceChildren(
    el('div', { class: 'two' },
      card('Adaptadores e MAC', null, el('div', { id: 'netA' })),
      card('Endereços IP', null, el('div', { id: 'netI' }))),
    el('div', { class: 'two', style: 'margin-top:14px' },
      card('Vizinhos (IP para MAC)', 'Tabela ARP: dispositivos vistos recentemente', el('div', { id: 'netN' })),
      card('DNS por interface', null, el('div', { id: 'netD' }))),
    el('div', { style: 'margin-top:14px' }, card('Rotas', null, el('div', { id: 'netR' }))),
    el('h3', { text: 'Saídas brutas' }),
    el('details', null, el('summary', { text: 'ipconfig /all' }), codeBlock(n.ipconfig)),
    el('details', null, el('summary', { text: 'route print' }), codeBlock(n.routeRaw)),
  );
  listView(document.getElementById('netA'), { search: false, cols: [{ k: 'Interface' }, { k: 'Description', label: 'Descrição' }, { k: 'MAC' }, { k: 'Status' }, { k: 'Speed', label: 'Velocidade' }], rows: n.adapters });
  listView(document.getElementById('netI'), { search: false, cols: [{ k: 'Interface' }, { k: 'Family', label: 'Família' }, { k: 'IP' }, { k: 'Prefix', label: 'Prefixo', num: true }, { k: 'Origin', label: 'Origem' }], rows: n.ips });
  listView(document.getElementById('netN'), { search: false, cols: [{ k: 'IP' }, { k: 'MAC' }, { k: 'State', label: 'Estado' }, { k: 'IfIndex', label: 'Índice', num: true }], rows: n.neighbors });
  listView(document.getElementById('netD'), { search: false, cols: [{ k: 'Interface' }, { k: 'Servers', label: 'Servidores' }], rows: n.dns });
  listView(document.getElementById('netR'), { cols: [{ k: 'Destination', label: 'Destino' }, { k: 'NextHop', label: 'Próximo salto' }, { k: 'Metric', label: 'Métrica', num: true }, { k: 'Interface' }, { k: 'Protocol', label: 'Origem' }], rows: n.routes });
}

// ---- Hosts ----
function renderHosts(host) {
  const h = D.hosts;
  host.replaceChildren(
    card('Arquivo hosts do Windows', 'Linhas destacadas são entradas ativas (não comentadas). Confira redirecionamentos.',
      kv([['Caminho', h.path], ['Entradas ativas', h.active]])),
    el('div', { style: 'margin-top:14px' }, el('div', { class: 'code', style: 'position:relative' },
      el('pre', { style: 'margin:0;white-space:pre;font:inherit;background:none;border:0;padding:0' },
        h.text.split(/\r?\n/).map(l => el('span', { class: l.trim() && !l.trim().startsWith('#') ? 'hl' : '', text: l + '\n' }))))));
}

// ---- Firewall ----
function renderFirewall(host) {
  const f = D.firewall;
  const box = el('div');
  host.replaceChildren(
    el('div', { class: 'cols-3' }, f.profiles.map(p => {
      const on = p.Enabled === 'True';
      return el('div', { class: 'card profile' },
        el('h4', null, p.Profile, pill(on ? 'Ativo' : 'Desligado', on ? 'p-low' : 'p-high')),
        kv([['Entrada padrão', p.DefaultInbound], ['Saída padrão', p.DefaultOutbound], ['Log de bloqueios', p.LogBlocked]]));
    })),
    note(`<b>Regras de bloqueio de entrada ativas:</b> ${f.blockRules}. <b>Amplas</b> = qualquer porta e qualquer programa. <b>Porta em escuta</b> = a regra cobre uma porta que está escutando agora.`),
    box);
  listView(box, {
    cols: [
      { k: 'Name', label: 'Regra' }, { k: 'Profile', label: 'Perfil' }, { k: 'Protocol', label: 'Protocolo' },
      { k: 'LocalPort', label: 'Porta local' }, { k: 'Remote', label: 'Remoto' }, { k: 'Program', label: 'Programa' },
      { k: 'Matches', label: 'Porta em escuta', render: r => r.Matches === 'Yes' ? pill('Sim', 'p-open') : el('span', { class: 'muted', text: 'Não' }) },
      { k: 'Broad', label: 'Ampla', render: r => r.Broad === 'Yes' ? pill('Sim', 'p-high') : el('span', { class: 'muted', text: 'Não' }) },
    ],
    rows: f.rules.map(r => ({ ...r, _search: `${r.Program} ${r.LocalPort}` })),
    filters: [
      { key: 'Broad', label: 'Amplas', all: 'Todas as regras', options: [['Yes', 'Só amplas'], ['No', 'Não amplas']] },
      { key: 'Matches', label: 'Porta em escuta', all: 'Todas', options: [['Yes', 'Com porta em escuta'], ['No', 'Sem porta em escuta']] },
    ],
    empty: 'Nenhuma regra com este filtro.',
  });
}

// ---- Captura ----
function renderCapture(host) {
  const c = D.capture;
  host.replaceChildren(
    card('Captura de tráfego', 'Opcional. Exige PowerShell como administrador.',
      kv([['Solicitada (segundos)', c.Requested], ['Status', c.Status], ['Observação', c.Note]]),
      c.Files.length ? el('ul', { class: 'plain mono', style: 'margin-top:12px' }, c.Files.map(f => el('li', { text: f }))) : null),
    el('div', { style: 'margin-top:14px' }, card('Como usar', null,
      el('ol', { class: 'plain' },
        el('li', null, 'Abra o PowerShell como administrador, na pasta do script.'),
        el('li', null, 'Rode ', el('code', { class: 'mono', text: '.\\local-scanner.ps1 -CaptureSeconds 30' }), '.'),
        el('li', null, 'Abra o arquivo .pcapng no Wireshark para ver origem, destino, porta e protocolo de cada pacote.'),
        el('li', null, 'A captura registra só cabeçalhos (128 bytes por pacote) e só deste computador.')),
      el('p', { class: 'muted', style: 'margin:12px 0 0', text: 'Não testado neste ambiente porque exige administrador. Se falhar, a mensagem de erro aparece acima.' }))));
}

// ---- Navegação e tema ----
const SECTION_DEFS = [
  ['resumo', 'Resumo', renderSummary, null], ['portas', 'Portas', renderPorts, D.listeners.length],
  ['conexoes', 'Conexões', renderConnections, D.connections.length], ['processos', 'Processos', renderProcesses, D.processes.length],
  ['rede', 'Rede', renderNetwork, null], ['hosts', 'Hosts', renderHosts, null],
  ['firewall', 'Firewall', renderFirewall, D.firewall.rules.length], ['captura', 'Captura', renderCapture, null],
];
let current = 'resumo';
function go(id) {
  const meta = SECTION_DEFS.find(s => s[0] === id) || SECTION_DEFS[0];
  current = meta[0];
  document.querySelectorAll('#nav button').forEach(b => b.setAttribute('aria-current', b.dataset.id === current ? 'page' : 'false'));
  document.querySelectorAll('section.view').forEach(s => s.hidden = s.id !== current);
  document.getElementById('title').textContent = meta[1];
  try { history.replaceState(null, '', '#' + current); } catch {}
  window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
}
const nav = document.getElementById('nav');
for (const [id, label, , count] of SECTION_DEFS) {
  nav.append(el('button', { 'data-id': id, onclick: () => go(id) },
    el('span', { text: label }), count != null ? el('span', { class: 'n', text: count }) : null));
}
for (const [id, , render] of SECTION_DEFS) render(document.getElementById(id));

document.getElementById('who').textContent = `${D.summary.Computer} · ${D.summary.User}`;
document.getElementById('gen').textContent = `Gerado em ${D.summary.Generated}` + (D.summary.IsAdmin ? ' · administrador' : ' · sem administrador (dados parciais)');
document.getElementById('expandAll').onclick = () => views.forEach(v => v.setAll(true));
document.getElementById('collapseAll').onclick = () => views.forEach(v => v.setAll(false));

const themeBtn = document.getElementById('theme');
function applyTheme(t) { document.documentElement.setAttribute('data-theme', t); themeBtn.textContent = t === 'light' ? 'Tema escuro' : 'Tema claro'; }
let savedTheme = 'dark';
try { savedTheme = localStorage.getItem('inspetor-tema') || 'dark'; } catch {}
applyTheme(savedTheme);
themeBtn.onclick = () => {
  const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  applyTheme(next);
  try { localStorage.setItem('inspetor-tema', next); } catch {}
};
document.getElementById('print').onclick = () => window.print();

document.addEventListener('keydown', e => {
  if (e.key === '/' && !/input|select|textarea/i.test(document.activeElement.tagName)) {
    const sec = document.querySelector('section.view:not([hidden]) input[type=search]');
    if (sec) { e.preventDefault(); sec.focus(); }
  }
});

go((location.hash || '#resumo').slice(1));
</script>
</body></html>
'@

$html = $template.Replace('__DATA__', $json)
[IO.File]::WriteAllText($report, $html, [Text.UTF8Encoding]::new($false))
Write-Host ('Relatório: ' + $report) -ForegroundColor Green
try { Start-Process $report } catch {}
if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) { Read-Host 'Pressione Enter para fechar' | Out-Null }
