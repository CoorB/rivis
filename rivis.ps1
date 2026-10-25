<#
<ProductName> — project-aware Proxyman replacement for Windows: mitmproxy + Android emulator.
Same security conditions as the macOS script: proxy on 127.0.0.1 only, never the Windows
system proxy, one CA per workstation, removed again with `off`.
(No iOS Simulator exists on Windows — iOS testing stays on the Macs.)

  .\<cli>.ps1 start [-Insecure] [-ProjectOnly] [-NoOpen] [-Project ID]
                                            mitmweb: proxy 127.0.0.1:8080, UI http://127.0.0.1:8083
  .\<cli>.ps1 stop | ui | status | cert
  .\<cli>.ps1 browser [URL] [-Browser chrome|edge|chromium|brave] [-Fresh] [-List]   (-Current: macOS CLI only)
                                            web apps: a separate browser window with its own profile, pointed
                                            at the proxy and trusting only this CA. Your normal browser, the
                                            system proxy and the certificate store are not touched
  .\<cli>.ps1 projects list|use|show|new
  .\<cli>.ps1 ui | rules list|on NAME|off NAME|show NAME|rm NAME|test URL [METHOD]|edit|allow-file PATH|disallow-file PATH|trusted-files
  .\<cli>.ps1 rules add NAME match=REGEX action=ACTION [key=value ...]
  .\<cli>.ps1 rules variant NAME add|use|rm VARIANT [file=PATH]
                                            manage hot-reloaded interception rules (json_patch: set='path=value' or set='{"path":value}')
  .\<cli>.ps1 scripts list|new NAME -Lang py|js [-Match REGEX]|on NAME|off NAME|edit NAME|rm NAME
  .\<cli>.ps1 throttle [off|3g-urban|lte-congested|high-latency-vpn|packet-loss-8|manual|lte|3g|edge|slow|<ms>ms[/<kbps>kbps]]
                         [match=REGEX] [loss=PCT] [latency_ms=N jitter_ms=N down_kbps=N up_kbps=N loss_pct=N response_delay_ms=N]
                         (-Match REGEX / -Loss PCT work too)
  .\<cli>.ps1 nocache on|off|status         No Caching: strip If-None-Match/If-Modified-Since... from requests and
                                            force no-store on responses (Map Local answers untouched)
  .\<cli>.ps1 tls list | mode all|allow|ignore | allow add|rm PATTERN | ignore add|rm PATTERN
  .\<cli>.ps1 tls client-cert list | add HOST FILE [-Key KEY_FILE] [-PasswordStdin] | rm HOST
                                            client certificate (mTLS) per host; FILE .p12/.pfx or PEM
                                            which hosts are decrypted (wildcards like *.example.test);
                                            hot-reloaded for NEW connections, no restart
  .\<cli>.ps1 compose list | send NAME [-Var name=value] [-NoWait]
                                            replay a request saved in the panel's Compose tab
  .\<cli>.ps1 breakpoint URL-REGEX [-Request|-Response] [-Method M] | off [NAME] | list
  .\<cli>.ps1 mock NAME URL-REGEX
  .\<cli>.ps1 mocks import-proxyman [PATH] [-DryRun]
  .\<cli>.ps1 android on|off [-Serial emulator-5554 | -All] [-ProxyOnly]
                                            Play images: the CA goes in by hand, then `android on -ProxyOnly`
  .\<cli>.ps1 setup                         configure every running Android emulator (iOS is unavailable on Windows)
  .\<cli>.ps1 net-reset [-DryRun] | status | cert
  .\<cli>.ps1 doctor [-Json] [-NoNet] [-FixSafe [-Yes]]
                                            read-only health check. Runs the shared Python checker when
                                            Python is installed; otherwise a reduced native subset
                                            (ports, WinINET/WinHTTP proxy, adb, mitmproxy version)
  .\<cli>.ps1 bug-report [-Output PATH]      create a redacted support bundle (no flows or tokens)

No openssl needed: the Android hash name (subject_hash_old) is computed here.
Environment names come from product.json; legacy NEO_MITM_* names remain fallbacks.
#>
param(
  [Parameter(Position=0)][string]$Command = "help",
  [Parameter(Position=1)][string]$Action = "",
  [Parameter(Position=2)][string]$Name = "",
  [string]$Serial = "",
  [string]$Project = "",
  [string]$Match = "",
  [string]$Label = "",
  [string]$Hosts = "",
  [string]$Output = "",
  [string]$FromCurl = "",
  [string]$Upstream = "",
  [ValidateSet("chrome","edge","chromium","brave")][string]$Browser = "",
  [Alias("-method")][string]$Method = "",
  [ValidateSet("py","js")][string]$Lang = "",
  [double]$Loss,
  [Alias("Dev")][switch]$Insecure,
  [Alias("NeoOnly")][switch]$ProjectOnly,
  [switch]$NoOpen,
  [switch]$DryRun,
  [switch]$NoWait,
  [switch]$Json,
  [switch]$NoNet,
  [switch]$AllowProfileNetwork,
  [switch]$FixSafe,
  [switch]$Yes,
  [switch]$ProxyOnly,
  [switch]$Fresh,
  [switch]$Current,
  [switch]$List,
  [Alias("-request")][switch]$Request,
  [Alias("-response")][switch]$Response,
  [Alias("-all")][switch]$All,
  [Alias("h","-help")][switch]$Help,
  [string[]]$Var = @(),
  [string]$Key = "",
  [switch]$PasswordStdin,
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$Rest = @()
)
$ErrorActionPreference = "Stop"
$ProductConfig = Get-Content -Raw (Join-Path $PSScriptRoot "product.json") | ConvertFrom-Json
$ProductName = $ProductConfig.name
$Cli = $ProductConfig.cli
$EnvPrefix = $ProductConfig.env_prefix
$PinnedMitmproxy = "12.2.3"
$MirrorConf = Join-Path $PSScriptRoot "install\mirror.conf"
if (Test-Path $MirrorConf) {
  $pin = Get-Content $MirrorConf | Where-Object { $_ -match '^MITMPROXY_VERSION=' } | Select-Object -First 1
  if ($pin -and $pin -match '^MITMPROXY_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$') { $PinnedMitmproxy = $Matches[1] }
}
function Config-Env($suffix, $fallback) {
  $value = [Environment]::GetEnvironmentVariable("${EnvPrefix}_$suffix")
  if (-not $value) { $value = [Environment]::GetEnvironmentVariable("NEO_MITM_$suffix") }
  if ($value) { return $value }
  return $fallback
}
$StateRoot = [Environment]::ExpandEnvironmentVariables(($ProductConfig.state_dir -replace '^~', $HOME))
$currentProject = Join-Path $StateRoot "current-project"
$projectSource = "argument"
if (-not $Project) { $Project = Config-Env "PROJECT" ""; $projectSource = "environment" }
if (-not $Project -and (Test-Path $currentProject)) { $Project = (Get-Content $currentProject -TotalCount 1).Trim(); $projectSource = "current-project" }
if (-not $Project) { $Project = "default" }
if ($Project -notmatch '^[a-z0-9][a-z0-9._-]{0,63}$') {
  if ($projectSource -eq "current-project") { Write-Warning "ignoring invalid current-project '$Project'; using default"; $Project = "default" }
  else { throw "invalid project ID '$Project'" }
}
function Profile-Dir($id) {
  $user = Join-Path (Join-Path $StateRoot "profiles") $id
  $repo = Join-Path (Join-Path $PSScriptRoot "projects") $id
  if (Test-Path (Join-Path $user "project.json")) { return $user }
  if (Test-Path (Join-Path $repo "project.json")) { return $repo }
  return $null
}
$ProfileDir = Profile-Dir $Project
if (-not $ProfileDir -and $projectSource -eq "current-project") {
  Write-Warning "current project '$Project' no longer exists; using default"
  $Project = "default"; $ProfileDir = Profile-Dir $Project
}
if (-not $ProfileDir) { throw "unknown project '$Project'" }
$ProjectConfig = Get-Content -Raw (Join-Path $ProfileDir "project.json") | ConvertFrom-Json
$Port    = Config-Env "PORT" 8080
$WebPort = Config-Env "WEB_PORT" 8083
$MaxFlowsText = Config-Env "MAX_FLOWS" 5000
$MaxFlows = 0
if (-not [int]::TryParse($MaxFlowsText, [ref]$MaxFlows) -or $MaxFlows -lt 1 -or $MaxFlows -gt 1000000) {
  throw "${EnvPrefix}_MAX_FLOWS must be an integer from 1 to 1000000"
}
$ConfDir = Config-Env "CONFDIR" (Join-Path $HOME ".mitmproxy")
$CaPem   = Join-Path $ConfDir "mitmproxy-ca-cert.pem"
$CaCer   = Join-Path $ConfDir "mitmproxy-ca-cert.cer"
$ProjectState = Join-Path (Join-Path $StateRoot "projects") $Project
$RulesPath = Config-Env "RULES" (Join-Path $ProjectState "rules.json")
# R4A-05: each web port keeps its own login (same names as the bash CLI), so a second instance cannot rotate the first's
$PortSuffix = if ("$WebPort" -eq "8083") { "" } else { "-$WebPort" }
$TokenPath = Join-Path $StateRoot "web-token$PortSuffix"
$BootstrapPath = Join-Path $StateRoot "web-bootstrap$PortSuffix"
$UpstreamPath = Join-Path $StateRoot "upstream-$WebPort"
function Get-Upstream {
  if ($Upstream) { return $Upstream }
  if (Test-Path $UpstreamPath) { return (Get-Content $UpstreamPath -TotalCount 1).Trim() }
  return "direct"
}
function Test-Upstream([string]$value) {
  if ($value -eq "direct") { return }
  $uri = $null
  if (-not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne "http" -or
      -not $uri.Host -or $uri.Port -lt 1 -or $uri.Port -gt 65535 -or $value -notmatch '^http://[^/]+:[0-9]+$' -or
      $uri.UserInfo -or $uri.Query -or $uri.Fragment) { Die "-Upstream needs an http://host:port URL without credentials or path" }
}

function Write-PrivateFile([string]$path, [string]$text) {
  # Write a private sibling and rename it into place: readers see the old or new complete file, never a partial one.
  $dir = Split-Path -Parent $path
  if (-not $dir) { $dir = "." }
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $tmp = Join-Path $dir (".write-" + [Guid]::NewGuid().ToString("N"))
  try {
    [IO.File]::WriteAllText($tmp, "", $Utf8NoBom)
    if (($PSVersionTable.PSEdition -eq "Desktop") -or $IsWindows) {
      & icacls.exe $tmp /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
      if ($LASTEXITCODE -ne 0) { Die "could not restrict access to $path" }
    } else { & chmod 600 $tmp }
    [IO.File]::WriteAllText($tmp, $text + [Environment]::NewLine, $Utf8NoBom)
    Move-Item -Force $tmp $path
  } finally { if (Test-Path $tmp) { Remove-Item -Force $tmp } }
}

$CaHistoryPath = Join-Path $StateRoot "ca-history"
function Get-CertSha256([string]$path) {
  # SHA256 of the DER bytes, upper-case hex (GetCertHashString(HashAlgorithmName) needs .NET 4.8, not always on PS 5.1)
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $path
  return (([System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData) | ForEach-Object { $_.ToString('X2') }) -join '')
}
function Add-CaHistory([string]$hash) {
  # lines "<sha256> <android-hash>", the same as the bash edition. Every mitmproxy CA has the same android hash,
  # so the sha256 is what tells them apart (`android off` removes only recorded fingerprints: review R3)
  if (-not $hash) { return }
  New-Item -ItemType Directory -Force -Path $StateRoot | Out-Null
  $entry = "$(if (Test-Path $CaCer) { Get-CertSha256 $CaCer } else { '-' }) $hash"
  $lines = @(if (Test-Path $CaHistoryPath) { Get-Content $CaHistoryPath })
  if ($lines -contains $entry) { return }
  Write-PrivateFile $CaHistoryPath (@($lines + $entry) -join [Environment]::NewLine)
}
function Get-CaHistoryShas {
  $shas = @(if (Test-Path $CaCer) { Get-CertSha256 $CaCer })
  if (Test-Path $CaHistoryPath) { $shas += @(Get-Content $CaHistoryPath | ForEach-Object { ($_ -split '\s+')[0] } | Where-Object { $_ -match '^[0-9A-Fa-f]{64}$' }) }
  return @($shas | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique)
}
function Get-CaHistoryHashes {
  if (-not (Test-Path $CaHistoryPath)) { return @() }
  return @(Get-Content $CaHistoryPath | ForEach-Object { ($_ -split '\s+')[1] } | Where-Object { $_ })
}

function Protect-StateRoot {
  # F-24: on shared Windows machines (RDS, terminal servers) the profile ACL may let others read the state dir.
  # Owner-only, inherited by everything below it. Done once; a marker avoids re-running icacls on every command.
  $marker = Join-Path $StateRoot ".acl-v1"
  if (Test-Path $marker) { return }
  if (($PSVersionTable.PSEdition -eq "Desktop") -or $IsWindows) {
    # No /T: with /T the (OI)(CI) entry lands on files that already exist as an inherit-only entry, and with the inherited
    # entries removed those files become unreadable ("Access denied" on rules.example.json after `projects new`). Without it
    # Windows propagates the new directory ACL to the existing children itself.
    & icacls.exe $StateRoot /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "WARNING: could not restrict $StateRoot to $($env:USERNAME) (icacls exit $LASTEXITCODE)"; return }
  } else {
    & chmod 700 $StateRoot
  }
  Write-PrivateFile $marker ""
}

function New-UiBootstrap {
  # one-time login link (addons\proxy_panel.py Bootstrap): the nonce is deleted on first use
  $bytes = New-Object byte[] 16
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  $nonce = (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
  Write-PrivateFile $BootstrapPath $nonce
  return "http://127.0.0.1:$WebPort/proxy/bootstrap/$nonce"
}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Info($m) { Write-Host "* $m" }
function Die($m)  { Write-Host "${Cli}: $m" -ForegroundColor Red; exit 1 }

function Write-Usage([string]$only = "") {
  $lines = @()
  foreach ($line in (Get-Content $PSCommandPath | Select-Object -Skip 1)) {
    if ($line -eq '#>') { break }
    $lines += (($line -replace '<cli>',$Cli) -replace '<ProductName>',$ProductName)
  }
  if (-not $only -or $only -in @("help","-h","--help")) { $lines | ForEach-Object { Write-Host $_ }; return }
  $selected = @(); $take = $false
  $prefix = ".\${Cli}.ps1 "
  foreach ($line in $lines) {
    $trimmed = $line.TrimStart()
    if ($trimmed.StartsWith($prefix)) {
      $commands = $trimmed.Substring($prefix.Length) -replace '\s{2,}.*$',''
      $take = $commands -match ("(^|[ |])" + [Regex]::Escape($only) + "([ |]|$)")
    }
    if ($take) { $selected += $line }
  }
  if ($selected.Count) { $selected | ForEach-Object { Write-Host $_ } }
  else { $lines | ForEach-Object { Write-Host $_ } }
}

function Get-PythonCommand {
  foreach ($candidate in @("py","python3","python")) {
    $command = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($command) {
      return [PSCustomObject]@{ Exe = $command.Source; Prefix = $(if ($candidate -eq "py") { @("-3") } else { @() }) }
    }
  }
  Die "Python is required for this command"
}

function Find-Adb {
  $c = Get-Command adb -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  foreach ($p in @("$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
                   "$env:ANDROID_HOME\platform-tools\adb.exe",
                   "$env:ANDROID_SDK_ROOT\platform-tools\adb.exe")) { if ($p -and (Test-Path $p)) { return $p } }
  Die "adb not found (Android SDK platform-tools)"
}

function Ensure-Ca {
  if (Test-Path $CaPem) { return }
  Info "no CA yet in $ConfDir - generating one"
  $p = Start-Process mitmdump -ArgumentList "--listen-host","127.0.0.1","--listen-port","0" -PassThru -WindowStyle Hidden
  for ($i=0; $i -lt 20 -and -not (Test-Path $CaPem); $i++) { Start-Sleep -Milliseconds 500 }
  Stop-Process $p -ErrorAction SilentlyContinue
  if (-not (Test-Path $CaPem)) { Die "CA was not generated in $ConfDir" }
}

# OpenSSL subject_hash_old = first 4 bytes of MD5(DER subject), little-endian, hex.
function Get-CaHash {
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CaCer
  $md5  = [System.Security.Cryptography.MD5]::Create().ComputeHash($cert.SubjectName.RawData)
  return ('{0:x2}{1:x2}{2:x2}{3:x2}' -f $md5[3], $md5[2], $md5[1], $md5[0])
}

function Port-Owner($p) {
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $c = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { $pr = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; return "$($pr.ProcessName) pid $($c.OwningProcess) $($c.LocalAddress):$p" }
    return $null
  }
  # NetTCPIP module missing (some stripped/older images): parse netstat instead
  $line = netstat -ano -p tcp | Select-String "LISTENING" | Where-Object { $_ -match "[:.]$p\s" } | Select-Object -First 1
  if ($line) { $f = ($line.ToString().Trim() -split '\s+'); $pr = Get-Process -Id $f[-1] -ErrorAction SilentlyContinue; return "$($pr.ProcessName) pid $($f[-1]) $($f[1])" }
  return $null
}

function Listening-Pids([int[]]$ports) {
  $pids = @()
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    foreach ($p in $ports) {
      $pids += @(Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $_.OwningProcess })
    }
  } elseif ($IsMacOS -and (Get-Command lsof -ErrorAction SilentlyContinue)) {   # pwsh on a Mac: netstat has no PIDs
    foreach ($p in $ports) { $pids += @(& lsof -t "-iTCP:$p" -sTCP:LISTEN 2>$null) }
  } else {
    foreach ($line in @(netstat -ano -p tcp | Select-String "LISTENING")) {
      $fields = $line.ToString().Trim() -split '\s+'
      if ($fields.Count -ge 5 -and ($ports | Where-Object { $fields[1] -match "[:.]$_$" })) { $pids += $fields[-1] }
    }
  }
  return @($pids | Where-Object { $_ } | Sort-Object -Unique)
}

function Test-OurMitmweb([int]$ProcessId) {
  $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
  if (-not $process -or -not ($process.ProcessName -eq "mitmweb")) { return $false }
  $commandLine = ""
  if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $record = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    if ($record) { $commandLine = [string]$record.CommandLine }
  } elseif (Get-Command ps -ErrorAction SilentlyContinue) {
    $commandLine = [string](& ps -ww -o args= -p $ProcessId 2>$null)
  }
  # R4A-05: "web-token" is a prefix of "web-token-8085": match the whole value and this instance's web port
  return ($commandLine -match ("proxy_auth_token_file=" + [regex]::Escape($TokenPath) + '(\s|$)')) -and
         ($commandLine -match ("web_port=$WebPort" + '(\s|$)'))
}

function Our-Listening-Pids([int[]]$ports) {
  return @(Listening-Pids $ports | Where-Object { Test-OurMitmweb ([int]$_) })
}

function Ensure-Rules {
  Migrate-Legacy
  foreach ($dir in @($StateRoot,$ProjectState,(Join-Path $ProjectState "mocks"),(Join-Path $ProjectState "collections"),(Join-Path $ProjectState "sessions"),(Join-Path $ProjectState "scripts"),(Join-Path $StateRoot "profiles"))) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  Protect-StateRoot
  if (Test-Path $RulesPath) { return }
  $rulesDir = Split-Path -Parent $RulesPath
  if (-not $rulesDir) { $rulesDir = "." }
  New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null
  $example = Join-Path $ProfileDir "rules.example.json"
  if (-not (Test-Path $example)) { Die "rules example not found: $example" }
  Copy-Item $example $RulesPath
  Info "created $RulesPath from project '$Project' (all rules off)"
}

# Rules and scripts load for the running project, which may differ from the selected project. Non-fatal; silent when the proxy is not running.
function Warn-RunningProject {
  if (-not (Test-Path $TokenPath)) { return }
  try {
    $token = (Get-Content -Raw $TokenPath).Trim()
    if (-not $token) { return }
    [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy
    $base = "http://127.0.0.1:$WebPort"
    Invoke-WebRequest -Uri "$base/?token=$([uri]::EscapeDataString($token))" -SessionVariable web -UseBasicParsing -TimeoutSec 3 | Out-Null
    $running = (Invoke-RestMethod -Uri "$base/proxy/api/state" -WebSession $web -UseBasicParsing -TimeoutSec 3).active_project
  } catch { return }
  if ($running -and $running -ne $Project) {
    [Console]::Error.WriteLine("${Cli}.ps1: warning: the running proxy serves project '$running', not '$Project' - changes to '$Project' apply only after: ${Cli}.ps1 -Project $Project stop, then start")
  }
}

function Migrate-Legacy {
  $old = Join-Path $HOME ".neo-mitm"
  $parent = Join-Path $StateRoot "projects"
  $target = Join-Path $parent "neo"
  if (-not (Test-Path $old) -or (Test-Path $target)) { return }
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  $temp = Join-Path $parent (".neo.tmp." + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $temp | Out-Null
  try {
    foreach ($item in @("rules.json","mocks","collections","sessions")) {
      $source = Join-Path $old $item
      if (Test-Path $source) { Copy-Item -Recurse $source (Join-Path $temp $item) }
    }
    $migratedRules = Join-Path $temp "rules.json"
    if (Test-Path $migratedRules) {
      try {
        $cfg = Get-Content -Raw $migratedRules | ConvertFrom-Json
        $changed = $false
        foreach ($rule in @($cfg.rules)) {
          foreach ($key in @("file","body_file")) {
            $property = $rule.PSObject.Properties[$key]
            if (-not $property -or -not $property.Value) { continue }
            $file = [string]$property.Value
            if ($file.StartsWith("~/") -or $file.StartsWith("~\")) { $file = Join-Path $HOME $file.Substring(2) }
            $oldMocks = Join-Path $old "mocks"
            $prefix = $oldMocks.TrimEnd([char[]]"\/") + [IO.Path]::DirectorySeparatorChar
            if ($file -eq $oldMocks -or $file.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
              $property.Value = (Join-Path $target "mocks") + $file.Substring($oldMocks.Length)
              $changed = $true
            }
          }
        }
        if ($changed) { Write-PrivateFile $migratedRules ($cfg | ConvertTo-Json -Depth 20) }
      } catch { Info "legacy rules copied unchanged because they are not valid JSON" }
    }
    Move-Item $temp $target
  } catch {
    throw "legacy state copy failed; migration will be retried next time: $($_.Exception.Message)"
  } finally {
    if (Test-Path $temp) { Remove-Item -Recurse -Force $temp }
  }
  Info "copied legacy ~/.neo-mitm state into $target (the original was left unchanged)"
}

function Read-RulesConfig {
  try { $cfg = Get-Content -Raw $RulesPath | ConvertFrom-Json }
  catch { Die "invalid rules JSON in ${RulesPath}: $($_.Exception.Message)" }
  if ($null -eq $cfg.schema_version) { $cfg | Add-Member -NotePropertyName schema_version -NotePropertyValue 1 }
  elseif (($cfg.schema_version -isnot [int] -and $cfg.schema_version -isnot [long]) -or $cfg.schema_version -lt 0) { Die "rules.json schema_version must be a non-negative integer" }
  elseif ($cfg.schema_version -gt 1) { Die "rules.json schema version $($cfg.schema_version) is newer than this Rivis supports (1); upgrade Rivis" }
  elseif ($cfg.schema_version -eq 0) { $cfg.schema_version = 1 }
  if ($null -eq $cfg.rules) { $cfg | Add-Member -NotePropertyName rules -NotePropertyValue @() }
  else { $cfg.rules = @($cfg.rules) }
  return $cfg
}

function Save-RulesConfig($cfg) {
  $cfg.rules = @($cfg.rules)
  if ($null -ne $cfg.scripts) { $cfg.scripts = @($cfg.scripts) }
  if ($null -eq $cfg.schema_version) { $cfg | Add-Member -NotePropertyName schema_version -NotePropertyValue 1 }
  $json = $cfg | ConvertTo-Json -Depth 20
  Write-PrivateFile $RulesPath $json
}

function Find-Rule($cfg, $ruleName) {
  $rule = @($cfg.rules) | Where-Object { $_.name -eq $ruleName } | Select-Object -First 1
  if (-not $rule) { Die "no rule named '$ruleName' (${Cli}.ps1 rules list)" }
  return $rule
}

function Format-JsonValue($value) {
  return (ConvertTo-Json -InputObject $value -Depth 20 -Compress)
}

function Show-Throttle($cfg) {
  $spec = if ($cfg.throttle) { $cfg.throttle } else { "off" }
  $filter = if ($cfg.throttle_match) { $cfg.throttle_match } else { "(all)" }
  $lossValue = if ($null -ne $cfg.loss) { $cfg.loss } else { 0 }
  Write-Host "throttle: $spec  match: $filter  loss: $lossValue%"
}

function Show-NoCache($cfg) {
  Write-Host ("No caching: " + $(if ($cfg.no_cache -eq $true) { "on" } else { "off" }))
}

$ThrottlePresets = @("off","3g-urban","lte-congested","high-latency-vpn","packet-loss-8","manual","lte","3g","edge","slow")
$ThrottleManualKeys = @("latency_ms","jitter_ms","down_kbps","up_kbps","loss_pct","response_delay_ms")
$TlsModes = @("all","allow","ignore")

function Convert-ToNumber($text, $what) {
  $n = 0.0
  if (-not [double]::TryParse($text, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { Die "$what must be a number, got '$text'" }
  $cap = if ($what -in @("loss","loss_pct")) { 100 } elseif ($what -in @("latency_ms","jitter_ms","response_delay_ms")) { 120000 } else { 1000000 }
  if ([double]::IsNaN($n) -or [double]::IsInfinity($n) -or $n -lt 0 -or $n -gt $cap) { Die "$what must be 0-$cap" }
  return $n
}

# Same validation as proxy_common.tls_host_regex (the add-on turns the pattern into an anchored regex).
function Test-TlsPattern([string]$pattern) {
  $p = $pattern.Trim().ToLowerInvariant().TrimEnd('.')
  if (-not $p -or $p.Contains('/') -or $p -match '\s') { Die "TLS host pattern must be a hostname such as *.example.test" }
  $hostPart = $p
  if (@($p.ToCharArray() | Where-Object { $_ -eq ':' }).Count -eq 1) {
    $i = $p.LastIndexOf(':'); $port = $p.Substring($i + 1)
    if ($port -match '^\d+$') {
      $portNumber = 0L
      if (-not [int64]::TryParse($port, [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) { Die "TLS host pattern port must be 1..65535" }
      $hostPart = $p.Substring(0, $i)
    }
  }
  if (-not $hostPart -or $hostPart.StartsWith('.') -or $hostPart.EndsWith('.')) { Die "TLS host pattern is not a valid hostname" }
  return $pattern.Trim().ToLowerInvariant()
}

function Get-Tls($cfg) {
  $mode = "all"; $allow = @(); $ignore = @()
  $block = $cfg.PSObject.Properties["tls"]
  if ($block -and $null -ne $block.Value) {
    if ($block.Value.mode) { $mode = ([string]$block.Value.mode).ToLowerInvariant() }
    if ($mode -notin $TlsModes) { Die "tls mode must be all, allow or ignore" }
    foreach ($item in @($block.Value.allow)) { if ($null -ne $item) { $allow += (Test-TlsPattern ([string]$item)) } }
    foreach ($item in @($block.Value.ignore)) { if ($null -ne $item) { $ignore += (Test-TlsPattern ([string]$item)) } }
  }
  return [ordered]@{ mode = $mode; allow = @($allow | Select-Object -Unique); ignore = @($ignore | Select-Object -Unique) }
}

function Save-Tls($cfg, $tls) {
  $block = [ordered]@{ mode = $tls.mode; allow = [object[]]@($tls.allow); ignore = [object[]]@($tls.ignore) }
  $cfg | Add-Member -NotePropertyName tls -NotePropertyValue ([PSCustomObject]$block) -Force
  Save-RulesConfig $cfg
}

# Native tools (adb, netsh) don't throw on failure in PowerShell 5.1 — check every call.
# The AVDs `android on` pointed at this proxy (same file as the bash edition): the running proxy puts the setting back
# on a listed emulator that comes back without one, e.g. after a cold boot. `android off` unlists it.
function Set-AndroidProxyMark($adb, $serial, [bool]$on) {
  $avd = ((& $adb -s $serial emu avd name 2>$null) -replace "`r","" | Where-Object { $_ -and $_ -ne "OK" } | Select-Object -First 1)
  if (-not ($avd -match '^[A-Za-z0-9._-]+$')) { return }
  $f = Join-Path $StateRoot "android-proxy"
  $list = @(if (Test-Path -LiteralPath $f) { Get-Content -LiteralPath $f | Where-Object { $_ -and $_ -ne $avd } })
  if ($on) { $list += $avd }
  Set-Content -LiteralPath $f -Value $list -Encoding ascii
}
function Run($what) { if ($LASTEXITCODE -ne 0) { Die "$what failed (exit $LASTEXITCODE)" } }

function Pick-Serial($adb) {
  if ($Serial) { $s = $Serial }
  else {
    $devices = & $adb devices; Run "adb devices"
    $s = $devices | Select-String '^(emulator-\d+)\s+device$' | ForEach-Object { $_.Matches[0].Groups[1].Value }
  }
  if (-not $s) { Die "no running emulator. Physical devices need a separate approval." }
  if (@($s).Count -gt 1) { Die "several emulators running - pass -Serial: $($s -join ' ')" }
  if ($s -notmatch '^emulator-\d+$') { Die "physical devices need a separate approval" }
  $q1 = ((& $adb -s $s shell getprop ro.kernel.qemu) -replace "`r","").Trim(); Run "verify emulator status"
  $q2 = ((& $adb -s $s shell getprop ro.boot.qemu) -replace "`r","").Trim(); Run "verify emulator status"
  if ($q1 -ne "1" -and $q2 -ne "1") { Die "physical devices need a separate approval" }
  return $s
}

function Test-StaleLocalProxy($spec) {
  if (-not $spec) { return $false }
  foreach ($part in @($spec -split ';')) {
    $endpoint = ($part -replace '^[^=]+=', '').Trim()
    $port = $null
    if ($endpoint -match '^\[::1\]:(\d+)$') { $port = $Matches[1] }
    elseif ($endpoint -match '^::1:(\d+)$') { $port = $Matches[1] }
    elseif ($endpoint -match '^(127\.0\.0\.1|localhost):(\d+)$') { $port = $Matches[2] }
    else { return $false }
    if (Port-Owner $port) { return $false }
  }
  return $true
}

# browser: a separate Chrome/Edge window for web apps, own profile, pinned to this CA (same as the bash `browser`)
$BrowserNames = [ordered]@{ chrome = "Google Chrome"; edge = "Microsoft Edge"; chromium = "Chromium"; brave = "Brave Browser" }
function Find-Browser([string]$id) {
  $override = Config-Env "BROWSER_APPS" ""
  if ($IsMacOS -or $override) {
    $roots = if ($override) { $override -split [IO.Path]::PathSeparator } else { @("/Applications", (Join-Path $HOME "Applications")) }
    $name = $BrowserNames[$id]
    foreach ($r in $roots) { $p = Join-Path $r "$name.app/Contents/MacOS/$name"; if ($r -and (Test-Path -LiteralPath $p -PathType Leaf)) { return $p } }
    return $null
  }
  $rel = @{ chrome = "Google\Chrome\Application\chrome.exe"; edge = "Microsoft\Edge\Application\msedge.exe"
            chromium = "Chromium\Application\chrome.exe"; brave = "BraveSoftware\Brave-Browser\Application\brave.exe" }[$id]
  foreach ($r in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
    if ($r) { $p = Join-Path $r $rel; if (Test-Path -LiteralPath $p -PathType Leaf) { return $p } }
  }
  return $null
}
function Get-DerLength([int]$n) {
  if ($n -lt 128) { return ,[byte[]]@($n) }
  if ($n -lt 256) { return ,[byte[]]@(0x81, $n) }
  return ,[byte[]]@(0x82, [byte]($n -shr 8), [byte]($n -band 0xff))
}
# base64(SHA-256(SubjectPublicKeyInfo)) of the CA — what Chrome's --ignore-certificate-errors-spki-list pins.
# Built by hand for RSA (the mitmproxy CA) so it also works on Windows PowerShell 5.1, which has no SPKI export.
function Get-CaSpki {
  $pk = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CaCer).PublicKey
  if ($pk.Oid.Value -eq "1.2.840.113549.1.1.1") {
    $key = $pk.EncodedKeyValue.RawData
    $alg = [byte[]]@(0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00)
    $bits = [byte[]](@(0x03) + (Get-DerLength ($key.Length + 1)) + @(0x00) + $key)
    $spki = [byte[]](@(0x30) + (Get-DerLength ($alg.Length + $bits.Length)) + $alg + $bits)
  } elseif ($pk.PSObject.Methods.Name -contains "ExportSubjectPublicKeyInfo") { $spki = $pk.ExportSubjectPublicKeyInfo() }
  else { Die "browser: unsupported CA key type $($pk.Oid.Value)" }
  return [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash($spki))
}
function Quote-Arg([string]$a) { return '"' + ($a -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' }

$helpTokens = @("-h","--help","-Help")
$helpRequested = $Help -or $Action -in $helpTokens -or $Name -in $helpTokens -or @($Rest | Where-Object { $_ -in $helpTokens }).Count
if ($helpRequested -or $Command -in @("-h","--help")) { Write-Usage $Command; exit 0 }
if ($Command -in @("version","--version") -or ($Command -eq "help" -and -not $Action -and @($Rest) -contains "--version")) {   # PowerShell binds a bare --version to $Rest      # installed copies carry VERSION at their root; a repo keeps it in install\
  $v = "dev"
  foreach ($f in @((Join-Path $PSScriptRoot "VERSION"), (Join-Path (Join-Path $PSScriptRoot "install") "VERSION"))) {
    if (Test-Path -LiteralPath $f) { $v = (Get-Content -Raw -LiteralPath $f).Trim(); break }
  }
  Write-Output "$($ProductConfig.cli) $v"; exit 0
}

if ($Command -notin @("help","cert","doctor","bug-report","-h","--help","")) { Migrate-Legacy }

$unexpected = @()
if ($Command -in @("start","stop","setup","ui","net-reset","doctor","bug-report","status","cert","help")) {
  if ($Action) { $unexpected += $Action }; if ($Name) { $unexpected += $Name }; $unexpected += @($Rest)
} elseif ($Command -eq "browser") {
  if ($Name) { $unexpected += $Name }; $unexpected += @($Rest)
} elseif ($Action -eq "list" -and $Command -in @("projects","rules","scripts","compose")) {
  if ($Name) { $unexpected += $Name }; $unexpected += @($Rest)
} elseif (@($Rest).Count -and $Command -ne "throttle" -and
          -not ($Command -eq "tls" -and $Action -in @("allow","ignore","client-cert")) -and
          -not ($Command -eq "rules" -and $Action -in @("add","variant")) -and
          -not ($Command -eq "rules" -and $Action -eq "test" -and @($Rest).Count -eq 1)) {
  $unexpected += @($Rest)
}
if ($unexpected.Count) { Die "unexpected argument(s): $($unexpected -join ' ')" }

switch ($Command) {
  "projects" {
    $subcommand = if ($Action) { $Action.ToLowerInvariant() } else { "list" }
    if ($subcommand -eq "list") {
      $items = @{}
      foreach ($base in @((Join-Path $PSScriptRoot "projects"),(Join-Path $StateRoot "profiles"))) {
        if (-not (Test-Path $base)) { continue }
        Get-ChildItem -Directory $base | Where-Object { -not $_.Name.StartsWith("_") } | ForEach-Object {
          $path = Join-Path $_.FullName "project.json"
          if (Test-Path $path) { $items[$_.Name] = Get-Content -Raw $path | ConvertFrom-Json }
        }
      }
      foreach ($id in @($items.Keys | Sort-Object)) {
        $mark = if ($id -eq $Project) { "*" } else { " " }
        Write-Host ("{0} {1,-16} {2,-18} {3}" -f $mark,$id,$items[$id].label,$items[$id].description)
      }
    } elseif ($subcommand -eq "use") {
      $id = $Name
      if (-not $id -or $id -notmatch '^[a-z0-9][a-z0-9._-]{0,63}$' -or -not (Profile-Dir $id)) { Die "unknown project '$id'" }
      New-Item -ItemType Directory -Force -Path $StateRoot | Out-Null
      Write-PrivateFile $currentProject $id
      Info "current project: $id (restart a running proxy to load its rules)"
    } elseif ($subcommand -eq "show") {
      $id = if ($Name) { $Name } else { $Project }
      if ($id -notmatch '^[a-z0-9][a-z0-9._-]{0,63}$') { Die "invalid project ID '$id'" }
      $dir = Profile-Dir $id
      if (-not $dir) { Die "unknown project '$id'" }
      Get-Content -Raw (Join-Path $dir "project.json")
    } elseif ($subcommand -eq "new") {
      $id = $Name
      if ($id -notmatch '^[a-z0-9][a-z0-9._-]{0,63}$' -or -not $Label -or -not $Hosts) { Die "usage: projects new ID -Label LABEL -Hosts REGEX" }
      try { [void](New-Object System.Text.RegularExpressions.Regex $Hosts) } catch { Die "invalid hosts regex" }
      $dir = Join-Path (Join-Path $StateRoot "profiles") $id
      if (Test-Path $dir) { Die "user profile '$id' already exists" }
      $temp = Join-Path (Join-Path $StateRoot "profiles") (".$id.tmp." + [Guid]::NewGuid().ToString("N"))
      try {
        New-Item -ItemType Directory -Force -Path $temp | Out-Null
        $doc = [ordered]@{ id=$id; label=$Label; description="User project profile"; hosts=$Hosts; record_match=$Hosts; throttle_match=$Hosts; dev_ssl_insecure_hint="use --insecure only when the upstream certificate cannot be validated"; android_packages=@(); ios_bundle_ids=@() }
        [IO.File]::WriteAllText((Join-Path $temp "project.json"), (($doc | ConvertTo-Json -Depth 10) + [Environment]::NewLine), $Utf8NoBom)
        $cfg = Get-Content -Raw (Join-Path $PSScriptRoot "projects\_template\rules.example.json") | ConvertFrom-Json
        $cfg.throttle_match = $Hosts; $cfg.collections.record_match = $Hosts
        [IO.File]::WriteAllText((Join-Path $temp "rules.example.json"), (($cfg | ConvertTo-Json -Depth 20) + [Environment]::NewLine), $Utf8NoBom)
        Move-Item $temp $dir
      } finally { if (Test-Path $temp) { Remove-Item -Recurse -Force $temp } }
      Info "created user profile $dir"
    } else { Die "usage: projects list|use ID|show [ID]|new ID -Label LABEL -Hosts REGEX" }
  }
  "start" {
    $chosenUpstream = Get-Upstream
    Test-Upstream $chosenUpstream
    $startMutex = [System.Threading.Mutex]::new($false, ("RivisStart-" + ($TokenPath -replace '[^A-Za-z0-9]','_')))
    if (-not $startMutex.WaitOne(0)) { $startMutex.Dispose(); Die "start already in progress on UI port $WebPort; retry after it finishes" }
    try {
    if (-not (Get-Command mitmweb -ErrorAction SilentlyContinue)) { Die "mitmweb not found (install mitmproxy from the internal mirror)" }
    Ensure-Ca
    Ensure-Rules
    $o = Port-Owner $Port; if ($o) { Die "port $Port already taken: $o" }
    $o = Port-Owner $WebPort; if ($o) { Die "UI port $WebPort already taken: $o" }
    if ($Upstream) { Write-PrivateFile $UpstreamPath $chosenUpstream }
    New-Item -ItemType Directory -Force -Path $StateRoot | Out-Null
    $token = Config-Env "WEB_PASSWORD" ""
    if (-not $token) {
      $bytes = New-Object byte[] 16
      $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
      try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
      $token = (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    # F-03: the password lives only in a private file read by addons\proxy_auth.py — never on argv (visible to
    # every local user) or in the output; the browser signs in through a one-time bootstrap link instead.
    Write-PrivateFile $TokenPath $token
    $url = "http://127.0.0.1:$WebPort/"
    $bootstrapUrl = New-UiBootstrap
    $proxyMode = if ($chosenUpstream -eq "direct") { "regular@$Port" } else { "upstream:$chosenUpstream@$Port" }
    $margs = @("--listen-host","127.0.0.1","--mode",$proxyMode,
              "--set","web_host=127.0.0.1","--set","web_port=$WebPort","--set","web_open_browser=false",
              "-s",(Join-Path $PSScriptRoot "addons\proxy_auth.py"),
              "--set","proxy_auth_token_file=$TokenPath","--set","proxy_bootstrap_file=$BootstrapPath",
              "--set","confdir=$ConfDir","--set","connection_strategy=lazy",
              "--set",("http2=" + $(if ((Config-Env "HTTP2" "0") -eq "1") { "true" } else { "false" })), "--set",("stream_large_bodies=" + (Config-Env "STREAM_LARGE_BODIES" "64m")),
              "-s",(Join-Path $PSScriptRoot "addons\proxy_rules.py"),"-s",(Join-Path $PSScriptRoot "addons\proxy_scripts.py"),"-s",(Join-Path $PSScriptRoot "addons\proxy_collections.py"),"-s",(Join-Path $PSScriptRoot "addons\proxy_source.py"),"-s",(Join-Path $PSScriptRoot "addons\proxy_panel.py"),"-s",(Join-Path $PSScriptRoot "addons\proxy_retention.py"),"-s",(Join-Path $PSScriptRoot "addons\proxy_operability.py"),
              "--set",("proxy_remember_ui=" + $(if ((Config-Env "REMEMBER_UI" "0") -eq "1") { "true" } else { "false" })),"--set","proxy_rules_file=$RulesPath","--set","proxy_project=$Project","--set","proxy_max_flows=$MaxFlows","--set","proxy_log_dir=$(Join-Path $StateRoot 'logs')")
    if ($Insecure) { $margs += @("--set","ssl_insecure=true"); Info "TLS: upstream verification OFF" }
    if ($ProjectOnly -and $ProjectConfig.hosts) {
      $escapedHosts = $ProjectConfig.hosts.Replace('\','\\').Replace("'","\'")
      $margs += @("--set","view_filter=~http & (~d '$escapedHosts')"); Info "view: $($ProjectConfig.label) calls only"
    }
    else { $margs += @("--set","view_filter=~http") }
    Info "proxy  127.0.0.1:$Port   (Android emulator: 10.0.2.2:$Port)"
    Info "upstream proxy: $chosenUpstream"
    Info "project $Project ($($ProjectConfig.label))"
    Info "rules  $RulesPath  (${Cli}.ps1 rules list)"
    Info "UI     $url (opens signed in; the password is never printed)"
    Info "       (reopen any time: .\${Cli}.ps1 ui)   - Ctrl-C to stop"
    if (-not $NoOpen) {
      $portOwnerDefinition = ${function:Port-Owner}.ToString()
      Start-Job -ArgumentList $bootstrapUrl,$WebPort,$portOwnerDefinition -ScriptBlock {
        param($uiUrl, $uiPort, $definition)
        Set-Item -Path Function:\Port-Owner -Value $definition
        for ($i = 0; $i -lt 40; $i++) {
          if (Port-Owner $uiPort) { Start-Process $uiUrl; break }
          Start-Sleep -Milliseconds 250
        }
      } | Out-Null
    }
    & mitmweb @margs
    } finally { $startMutex.ReleaseMutex(); $startMutex.Dispose() }
  }
  "stop" {
    $stopped = 0
    $stoppedPids = @()
    foreach ($ownerPid in @(Our-Listening-Pids @([int]$Port,[int]$WebPort))) {
      try { Stop-Process -Id $ownerPid -ErrorAction Stop; $stoppedPids += $ownerPid; $stopped++ }
      catch { Die "could not stop mitmweb pid ${ownerPid}: $($_.Exception.Message)" }
    }
    if ($stopped) {
      try { Wait-Process -Id $stoppedPids -Timeout 10 -ErrorAction Stop }
      catch {
        foreach ($ownerPid in @(Our-Listening-Pids @([int]$Port,[int]$WebPort))) {
          Stop-Process -Id $ownerPid -Force -ErrorAction SilentlyContinue
        }
      }
      for ($i = 0; $i -lt 20 -and -not (Ports-Free @([int]$Port,[int]$WebPort)); $i++) {
        Start-Sleep -Milliseconds 100
      }
      if (-not (Ports-Free @([int]$Port,[int]$WebPort))) { Die "ports $Port/$WebPort are still in use after stopping mitmweb" }
      Info "stopped mitmweb on :$Port/:$WebPort"
    }
    else { Info "nothing to stop on :$Port/:$WebPort" }
  }
  "ui" {
    if (-not (Port-Owner $WebPort)) { Die "mitmweb is not running - ${Cli}.ps1 start" }
    if (-not (Test-Path $TokenPath)) { Die "no token file - restart with ${Cli}.ps1 start" }
    Start-Process (New-UiBootstrap)
  }
  "rules" {
    Ensure-Rules
    Warn-RunningProject
    $cfg = Read-RulesConfig
    $subcommand = if ($Action) { $Action.ToLowerInvariant() } else { "list" }
    if ($subcommand -eq "list") {
      $spec = if ($cfg.throttle) { $cfg.throttle } else { "off" }
      $filter = if ($cfg.throttle_match) { "  (match $($cfg.throttle_match))" } else { "" }
      $lossValue = if ($null -ne $cfg.loss) { $cfg.loss } else { 0 }
      Write-Host "throttle: $spec$filter   loss: $lossValue%"
      Write-Host "rules ($RulesPath):"
      $rules = @($cfg.rules)
      if ($rules.Count -eq 0) { Write-Host "  (none)"; break }
      foreach ($rule in $rules) {
        $state = if ($rule.enabled -eq $false) { "off" } else { "ON" }
        $method = if ($rule.method) { "$($rule.method) " } else { "" }
        $ruleMatch = if ($null -ne $rule.match) { $rule.match } else { "." }
        $extra = @()
        foreach ($property in $rule.PSObject.Properties) {
          if ($property.Name -notin @("name","enabled","match","action","method","note")) {
            $extra += "$($property.Name)=$(Format-JsonValue $property.Value)"
          }
        }
        Write-Host ("  {0,-3} {1,-24} {2,-10} {3}{4}  {5}" -f $state,$rule.name,$rule.action,$method,$ruleMatch,($extra -join " "))
      }
    } elseif ($subcommand -eq "edit") {
      Start-Process notepad.exe -ArgumentList ('"{0}"' -f $RulesPath) -Wait
      try { Get-Content -Raw $RulesPath | ConvertFrom-Json | Out-Null }
      catch { Die "file is no longer valid JSON: $($_.Exception.Message) - the proxy keeps the previous rules until fixed" }
    } elseif ($subcommand -eq "test") {
      # what each rule would do to this call; nothing is sent (same explanation as the panel's Test button)
      if (-not $Name) { Die "usage: rules test URL [METHOD]" }
      $python = Get-PythonCommand
      $testArgs = @($Name)
      if ($Method) { $testArgs += $Method } elseif (@($Rest).Count) { $testArgs += [string]@($Rest)[0] }
      & $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\rules_cli.py") $RulesPath rules test @testArgs
      if ($LASTEXITCODE) { exit $LASTEXITCODE }
    } elseif ($subcommand -eq "add") {
      $ruleName = if ($Name) { $Name } elseif ($args.Count -gt 0) { [string]$args[0] } else { "" }
      if (-not $ruleName) { Die "usage: rules add NAME match=REGEX action=ACTION [key=value ...]" }
      $python = Get-PythonCommand
      $addArgs = @($ruleName)
      if ($Match -and -not (@($Rest) -match '^match=')) { $addArgs += "match=$Match" }
      if ($Method -and -not (@($Rest) -match '^method=')) { $addArgs += "method=$Method" }
      if (@($Rest).Count) { $addArgs += @($Rest) }
      $previousProject = [Environment]::GetEnvironmentVariable("RIVIS_ACTIVE_PROJECT")
      $previousConf = [Environment]::GetEnvironmentVariable("RIVIS_RULE_CONFDIR")
      try {
        $env:RIVIS_ACTIVE_PROJECT = $Project
        $env:RIVIS_RULE_CONFDIR = $ConfDir
        & $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\rules_cli.py") $RulesPath rules add @addArgs
        if ($LASTEXITCODE) { exit $LASTEXITCODE }
      } finally {
        [Environment]::SetEnvironmentVariable("RIVIS_ACTIVE_PROJECT", $previousProject)
        [Environment]::SetEnvironmentVariable("RIVIS_RULE_CONFDIR", $previousConf)
      }
    } elseif ($subcommand -eq "variant") {
      if (-not $Name -or @($Rest).Count -lt 2) { Die "usage: rules variant NAME add|use|rm VARIANT [file=PATH]" }
      $python = Get-PythonCommand
      $arguments = @("rules", "variant", $Name) + @($Rest)
      $previousProject = [Environment]::GetEnvironmentVariable("RIVIS_ACTIVE_PROJECT")
      $previousConf = [Environment]::GetEnvironmentVariable("RIVIS_RULE_CONFDIR")
      try {
        $env:RIVIS_ACTIVE_PROJECT = $Project
        $env:RIVIS_RULE_CONFDIR = $ConfDir
        & $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\rules_cli.py") $RulesPath @arguments
        if ($LASTEXITCODE) { exit $LASTEXITCODE }
      } finally {
        [Environment]::SetEnvironmentVariable("RIVIS_ACTIVE_PROJECT", $previousProject)
        [Environment]::SetEnvironmentVariable("RIVIS_RULE_CONFDIR", $previousConf)
      }
    } elseif ($subcommand -in @("allow-file","disallow-file","trusted-files")) {
      # Map Local / body_file outside the project: only files trusted here, in a list rules.json cannot write (F-09).
      $trustPath = Join-Path (Split-Path -Parent $RulesPath) "trusted-files.json"
      $files = @()
      if (Test-Path $trustPath) { try { $files = @((Get-Content -Raw $trustPath | ConvertFrom-Json).files) } catch { $files = @() } }
      if ($subcommand -eq "trusted-files") {
        if ($files.Count) { $files | ForEach-Object { Write-Host $_ } } else { Write-Host "(no files outside the project are trusted)" }
        break
      }
      $target = if ($Name) { $Name } elseif ($args.Count -gt 0) { [string]$args[0] } else { "" }
      if (-not $target) { Die "usage: rules $subcommand PATH" }
      $full = [IO.Path]::GetFullPath($target)
      if ($subcommand -eq "allow-file") {
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Die "file not found: $target" }
        $item = Get-Item -LiteralPath $full -Force
        if ($item.LinkType) { Die "refusing to trust ${target}: it is a link; trust the file it points to" }
        $deny = @((Join-Path $HOME ".mitmproxy"), (Join-Path $HOME ".ssh"), (Join-Path $HOME ".aws"), (Join-Path $HOME ".gnupg"),
                  (Join-Path $HOME ".kube"), (Join-Path $HOME ".docker"), $ConfDir) | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\','/') }
        foreach ($d in $deny) {
          if ($full.StartsWith($d + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { Die "refusing to trust ${target}: it is inside $d (keys and credentials)" }
        }
        $leaf = [IO.Path]::GetFileName($full).ToLowerInvariant()
        if ($leaf -in @("web-token","web-bootstrap","trusted-files.json") -or $leaf -match '^web-(token|bootstrap)-[0-9]+$' -or $leaf -match '\.(pem|p12|pfx|key)$') { Die "refusing to trust ${target}: it looks like a key or a $ProductName secret" }
        $files = @($files | Where-Object { $_ -ne $full }) + $full
        Write-Host "trusted on this machine: $full - rules may now read it"
      } else {
        $files = @($files | Where-Object { $_ -ne $full })
        Write-Host "no longer trusted: $full"
      }
      $trustDoc = ConvertTo-Json -InputObject @{ files = @($files | Sort-Object) } -Depth 3
      Write-PrivateFile $trustPath $trustDoc
      if (Test-Path $RulesPath) { (Get-Item $RulesPath).LastWriteTime = Get-Date }   # hot reload
    } elseif ($subcommand -in @("on","off","show","rm")) {
      $ruleName = if ($Name) { $Name } elseif ($args.Count -gt 0) { [string]$args[0] } else { "" }
      if (-not $ruleName) { Die "usage: rules $subcommand NAME" }
      $rule = Find-Rule $cfg $ruleName
      if ($subcommand -eq "show") {
        Write-Host ($rule | ConvertTo-Json -Depth 20)
      } elseif ($subcommand -eq "rm") {
        $python = Get-PythonCommand
        $previousProject = [Environment]::GetEnvironmentVariable("RIVIS_ACTIVE_PROJECT")
        try {
          $env:RIVIS_ACTIVE_PROJECT = $Project
          & $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\rules_cli.py") $RulesPath rules rm $ruleName
          if ($LASTEXITCODE) { exit $LASTEXITCODE }
        } finally {
          [Environment]::SetEnvironmentVariable("RIVIS_ACTIVE_PROJECT", $previousProject)
        }
      } else {
        $rule | Add-Member -NotePropertyName enabled -NotePropertyValue ($subcommand -eq "on") -Force
        if ($subcommand -eq "on") { $rule.PSObject.Properties.Remove("draft") }
        Save-RulesConfig $cfg
        Write-Host "$ruleName -> $($subcommand.ToUpperInvariant())"
      }
    } else {
      Die "unknown rules command '$subcommand'"
    }
  }
  "scripts" {
    Ensure-Rules
    Warn-RunningProject
    $cfg = Read-RulesConfig
    if ($null -eq $cfg.scripts) { $cfg | Add-Member -NotePropertyName scripts -NotePropertyValue @() -Force }
    else { $cfg.scripts = @($cfg.scripts) }
    $subcommand = if ($Action) { $Action.ToLowerInvariant() } else { "list" }
    $scriptDir = Join-Path $ProjectState "scripts"
    New-Item -ItemType Directory -Force -Path $scriptDir | Out-Null
    if ($subcommand -eq "list") {
      Write-Host "scripts (${scriptDir}):"
      if (-not @($cfg.scripts).Count) { Write-Host "  (none)"; break }
      foreach ($script in @($cfg.scripts | Sort-Object file)) {
        $state = if ($script.enabled -eq $false) { "off" } else { "ON " }
        Write-Host ("  {0} {1,-24} {2,-2} {3,-6} {4}  {5}" -f $state,$script.name,$script.lang,$(if ($script.method) {$script.method} else {"ANY"}),$(if ($script.match) {$script.match} else {"."}),$script.file)
      }
      break
    }
    if (-not $Name -or $Name -notmatch '^[A-Za-z0-9._-]{1,64}$') { Die "scripts $subcommand requires a safe NAME" }
    $script = @($cfg.scripts | Where-Object { $_.name -eq $Name -or $_.file -eq $Name }) | Select-Object -First 1
    if ($subcommand -eq "new") {
      if (-not $Lang) { Die "scripts new NAME requires -Lang py|js" }
      try { [void](New-Object System.Text.RegularExpressions.Regex $(if ($Match) {$Match} else {"."})) } catch { Die "bad regex in match: $($_.Exception.Message)" }
      $filename = "$Name.$Lang"; $path = Join-Path $scriptDir $filename
      if ($script -or (Test-Path $path)) { Die "script already exists" }
      $source = if ($Lang -eq "py") {
        'def on_request(context, url, request):' + "`n" + '    request["headers"]["X-QA"] = "enabled"' + "`n" + '    return request' + "`n"
      } else {
        'async function onRequest(context, url, request) {' + "`n" + '  request.headers["X-QA"] = "enabled";' + "`n" + '  return request;' + "`n" + '}' + "`n"
      }
      Write-PrivateFile $path $source.TrimEnd("`r","`n")
      $cfg.scripts += [PSCustomObject]@{name=$Name;file=$filename;lang=$Lang;enabled=$true;match=$(if ($Match) {$Match} else {"."});method=$null}
      Save-RulesConfig $cfg; Write-Host "created $path"
    } elseif (-not $script) { Die "no script named '$Name'" }
    elseif ($subcommand -in @("on","off")) {
      $script | Add-Member -NotePropertyName enabled -NotePropertyValue ($subcommand -eq "on") -Force
      Save-RulesConfig $cfg; Write-Host "$($script.name) -> $($subcommand.ToUpperInvariant())"
    } elseif ($subcommand -eq "edit") {
      Start-Process notepad.exe -ArgumentList ('"{0}"' -f (Join-Path $scriptDir $script.file)) -Wait
    } elseif ($subcommand -eq "rm") {
      $cfg.scripts = @($cfg.scripts | Where-Object { $_ -ne $script }); Save-RulesConfig $cfg
      $path = Join-Path $scriptDir $script.file; if (Test-Path $path) { Remove-Item $path }
      Write-Host "removed $($script.name)"
    } else {
      Die "unknown scripts command '$subcommand'"
    }
  }
  "throttle" {
    Ensure-Rules
    Warn-RunningProject
    $cfg = Read-RulesConfig
    $extras = @(); if ($Name) { $extras += $Name }; $extras += @($Rest)
    if (-not $Action) { Show-Throttle $cfg; break }
    $spec = $Action.ToLowerInvariant()
    if ($spec -notin $ThrottlePresets -and $spec -notmatch '^\d+ms(/\d+kbps)?$') {
      Die ("throttle: " + ($ThrottlePresets -join " | ") + " | <ms>ms[/<kbps>kbps]")
    }
    $cfg | Add-Member -NotePropertyName throttle -NotePropertyValue $spec -Force
    $cfg | Add-Member -NotePropertyName loss -NotePropertyValue 0 -Force
    $scope = if ($ProjectConfig.throttle_match -and $ProjectConfig.throttle_match.Trim() -ne ".") { $ProjectConfig.throttle_match.Trim() } else { "" }
    $cfg | Add-Member -NotePropertyName throttle_match -NotePropertyValue $scope -Force
    foreach ($kv in $extras) {
      $key, $val = $kv -split '=', 2
      if ($kv -notmatch '=') { Die "throttle: expected key=value, got '$kv'" }
      if ($key -eq "match") { $Match = $val; $PSBoundParameters["Match"] = $val }
      elseif ($key -eq "loss") { $Loss = Convert-ToNumber $val "loss"; $PSBoundParameters["Loss"] = $Loss }
      elseif ($key -in $ThrottleManualKeys) {
        if ($null -eq $cfg.PSObject.Properties["manual"] -or $null -eq $cfg.manual) { $cfg | Add-Member -NotePropertyName manual -NotePropertyValue ([PSCustomObject]@{}) -Force }
        $cfg.manual | Add-Member -NotePropertyName $key -NotePropertyValue (Convert-ToNumber $val $key) -Force   # used when the profile is "manual"
      }
      else { Die "throttle options: match=REGEX loss=PCT, and for manual: $($ThrottleManualKeys -join '= ')=" }
    }
    if ($PSBoundParameters.ContainsKey("Match")) {
      try { [void](New-Object System.Text.RegularExpressions.Regex $Match) } catch { Die "bad regex in match: $($_.Exception.Message)" }
      $cfg | Add-Member -NotePropertyName throttle_match -NotePropertyValue $Match -Force
    }
    if ($PSBoundParameters.ContainsKey("Loss")) { $cfg | Add-Member -NotePropertyName loss -NotePropertyValue $Loss -Force }
    Save-RulesConfig $cfg
    Show-Throttle $cfg
  }
  "nocache" {
    Ensure-Rules
    Warn-RunningProject
    $cfg = Read-RulesConfig
    $sub = if ($Action) { $Action.ToLowerInvariant() } else { "status" }
    if ($Name -or $sub -notin @("on","off","status")) { Die "nocache: on | off | status" }
    if ($sub -ne "status") {
      $cfg | Add-Member -NotePropertyName no_cache -NotePropertyValue ($sub -eq "on") -Force
      Save-RulesConfig $cfg
    }
    Show-NoCache $cfg
  }
  "tls" {
    Ensure-Rules
    Warn-RunningProject
    $cfg = Read-RulesConfig
    $tls = Get-Tls $cfg
    $sub = if ($Action) { $Action.ToLowerInvariant() } else { "list" }
    if ($sub -eq "client-cert") {   # client certificates (mTLS) per host, kept in the project's private state
      $ccArgs = @($(if ($Name) { $Name } else { "list" })) + @($Rest)
      if ($Key) { $ccArgs += @("--key", $Key) }
      if ($PasswordStdin) { $ccArgs += "--password-stdin" }
      $python = Get-PythonCommand
      & $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\client_certs.py") (Join-Path $ProjectState "client-certs") @ccArgs
      exit $LASTEXITCODE
    }
    $tlsNote = "applies to new connections after the next rules poll; allow a few seconds - no restart; open connections keep their earlier decision"
    if ($sub -eq "list") {
      Write-Host "tls mode: $($tls.mode)"
      foreach ($which in @("allow","ignore")) {
        Write-Host ("{0}{1}:" -f $which, $(if ($tls.mode -eq $which) { "  (active)" } else { "  (used when mode is $which)" }))
        foreach ($item in @($tls[$which])) { Write-Host "  $item" }
        if (-not @($tls[$which]).Count) { Write-Host "  (none)" }
      }
      if ($tls.mode -eq "all") { Write-Host "all hosts are decrypted; hosts that are not decrypted show as host-only tunnel rows in the other modes" }
      break
    }
    if ($sub -eq "mode") {
      if (-not $Name) { Write-Host "tls mode: $($tls.mode)"; break }
      $newMode = $Name.ToLowerInvariant()
      if ($newMode -notin $TlsModes) { Die "tls mode must be all, allow or ignore" }
      $tls.mode = $newMode; $message = "tls mode: $newMode"
    } elseif ($sub -in @("allow","ignore")) {
      $verb = if ($Name) { $Name.ToLowerInvariant() } else { "" }
      $pattern = if (@($Rest).Count -eq 1) { $Rest[0] } else { "" }
      if ($verb -notin @("add","rm") -or -not $pattern) { Die "tls $sub add|rm PATTERN" }
      $pattern = Test-TlsPattern $pattern
      if ($verb -eq "add") { if ($pattern -notin @($tls[$sub])) { $tls[$sub] = @(@($tls[$sub]) + $pattern) }; $message = "$sub added: $pattern" }
      else { $tls[$sub] = @(@($tls[$sub]) | Where-Object { $_ -ne $pattern }); $message = "$sub removed: $pattern" }
    } else { Die "tls list | mode all|allow|ignore | allow add|rm PATTERN | ignore add|rm PATTERN" }
    Save-Tls $cfg $tls
    Write-Host $message
    if ($tls.mode -ne "all" -and -not @($tls[$tls.mode]).Count) { Write-Host "note: mode is $($tls.mode) but the $($tls.mode) list is empty$(if ($tls.mode -eq 'allow') { ' - nothing would be decrypted' })" }
    Write-Host $tlsNote
  }
  "compose" {
    if ($FromCurl) {
      if ($Action -or $Name) { Die "compose -FromCurl FILE|-" }
      $python = Get-PythonCommand
      & $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\compose_cli.py") from-curl $FromCurl
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
      break
    }
    $sub = if ($Action) { $Action.ToLowerInvariant() } else { "list" }
    $composeDir = Join-Path $ProjectState "composer"
    if ($sub -eq "list") {
      $files = @(); if (Test-Path $composeDir) { $files = @(Get-ChildItem -File -Filter *.json $composeDir | Where-Object { $_.Name -ne "vars.json" -and $_.BaseName -match '^[A-Za-z0-9._-]{1,64}$' } | Sort-Object Name) }
      if (-not $files.Count) { Write-Host "(no saved requests in $composeDir)" }
      foreach ($file in $files) {
        try { $saved = Get-Content -Raw $file.FullName | ConvertFrom-Json; Write-Host ("  {0,-24} {1,-7} {2}" -f $file.BaseName, $(if ($saved.method) { $saved.method } else { "GET" }), $saved.url) }
        catch { Write-Host ("  {0,-24} (unreadable)" -f $file.BaseName) }
      }
      $varsFile = Join-Path $composeDir "vars.json"
      if (Test-Path $varsFile) {
        try { $names = @((Get-Content -Raw $varsFile | ConvertFrom-Json).PSObject.Properties.Name | Sort-Object); if ($names.Count) { Write-Host ("variables: " + ($names -join ", ")) } }
        catch { Write-Host "variables: unreadable ($($_.Exception.Message))" }
      }
    } elseif ($sub -eq "send") {
      if (-not $Name -or $Name -notmatch '^[A-Za-z0-9._-]{1,64}$' -or $Name -eq "vars") { Die "compose send NAME [-Var name=value] [-NoWait]" }
      if (-not (Test-Path (Join-Path $composeDir "$Name.json"))) { Die "no saved request '$Name' (${Cli}.ps1 compose list)" }
      if (-not (Test-Path $TokenPath)) { Die "no token file $TokenPath - is the proxy running? (${Cli}.ps1 start)" }
      $token = (Get-Content -Raw $TokenPath).Trim()
      $overrides = @{}
      foreach ($item in @($Var)) { $k, $v = $item -split '=', 2; if ($item -notmatch '=') { Die "-Var expects name=value" }; $overrides[$k] = $v }
      [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy   # direct to 127.0.0.1, never via a system proxy
      $base = "http://127.0.0.1:$WebPort"
      try { Invoke-WebRequest -Uri "$base/?token=$token" -SessionVariable web -UseBasicParsing | Out-Null }
      catch { Die "cannot reach the proxy UI on 127.0.0.1:$WebPort ($($_.Exception.Message)) - is it running?" }
      $xsrf = ($web.Cookies.GetCookies($base) | Where-Object { $_.Name -eq "_mitmproxy_xsrf" } | Select-Object -First 1).Value
      if (-not $xsrf) { Die "mitmweb gave no XSRF cookie - token rejected? restart the proxy or run ${Cli}.ps1 ui" }
      try { $running = (Invoke-RestMethod -Uri "$base/proxy/api/state" -WebSession $web -UseBasicParsing).active_project }
      catch { Die "cannot read the proxy state ($($_.Exception.Message))" }
      if ($running -ne $Project) { Die "the running proxy serves project '$running', not '$Project' - restart it with -Project $Project (or use -Project $running)" }
      $body = (@{ name = $Name; vars = $overrides } | ConvertTo-Json -Depth 5 -Compress)
      try { $sent = Invoke-RestMethod -Uri "$base/proxy/api/compose_send" -Method Post -WebSession $web -ContentType "application/json" -Headers @{ "X-XSRFToken" = $xsrf } -Body $body -UseBasicParsing }
      catch {
        $detail = $null
        try { $detail = ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch { }
        Die "compose_send failed: $(if ($detail) { $detail } else { $_.Exception.Message })"
      }
      Write-Host "sent $($sent.method) $($sent.url)"
      if (-not $NoWait) {
        for ($i = 0; $i -lt 40; $i++) {
          Start-Sleep -Milliseconds 500
          try { $flow = Invoke-RestMethod -Uri "$base/flows/$($sent.id)" -WebSession $web -UseBasicParsing } catch { continue }
          if ($flow.error) { Die "call failed: $($flow.error.msg)" }
          if ($flow.response) { Write-Host "-> $($flow.response.status_code)"; break }
          if ($i -eq 39) { Write-Host "no response yet - check the proxy list" }
        }
      }
    } else { Die "compose list | send NAME" }
  }
  "breakpoint" {
    Ensure-Rules
    Warn-RunningProject
    $arguments = @()
    if ($Action -and $Action.ToLowerInvariant() -ne "list") { $arguments += $Action }
    if ($Name) { $arguments += $Name }
    $arguments += @($Rest)
    if ($Request) { $arguments += "--request" }
    if ($Response) { $arguments += "--response" }
    if ($Method) { $arguments += @("--method",$Method) }
    $python = Get-PythonCommand
    & $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\rules_cli.py") $RulesPath breakpoint @arguments
    exit $LASTEXITCODE
  }
  "mocks" {
    if ($Action -ne "import-proxyman") { Die "usage: ${Cli}.ps1 mocks import-proxyman [PATH] [-DryRun]" }
    Ensure-Rules
    $python = Get-PythonCommand
    $arguments = @("import-proxyman")
    if ($Name) { $arguments += $Name }
    if ($DryRun) { $arguments += "--dry-run" }
    & $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\rules_cli.py") $RulesPath mocks @arguments
    exit $LASTEXITCODE
  }
  "mock" {
    if (-not $Action -or -not $Name -or @($Rest).Count) { Die "usage: ${Cli}.ps1 mock NAME URL-REGEX   (run the journey once first so the call is captured)" }
    if ($Action -notmatch '^[A-Za-z0-9._-]{1,64}$' -or $Action.StartsWith('.')) { Die "name '$Action': letters, digits, . _ - only (max 64, not starting with .)" }
    Ensure-Rules
    if (-not (Port-Owner $WebPort)) { Die "mitmweb is not running - ${Cli}.ps1 start" }
    if (-not (Test-Path $TokenPath)) { Die "no token file - restart with ${Cli}.ps1 start" }
    $token = (Get-Content -Raw $TokenPath).Trim()
    $temp = [IO.Path]::GetTempFileName()
    $python = Get-PythonCommand
    try {
      try { Invoke-WebRequest -Uri "http://127.0.0.1:$WebPort/flows?token=$token" -OutFile $temp -UseBasicParsing }
      catch { Die "could not read the captured calls" }
      $pick = @(& $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\rules_cli.py") $RulesPath mock-pick $Action $Name $temp)
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally { if (Test-Path $temp) { Remove-Item -Force $temp } }
    if ($pick.Count -ne 4) { Die "could not identify the captured response" }
    $id,$status,$method,$headers = $pick
    $mockDir = Join-Path $ProjectState "mocks"
    New-Item -ItemType Directory -Force -Path $mockDir | Out-Null
    $file = Join-Path $mockDir "$Action.json"
    $createdMock = if (Test-Path $file) { 0 } else { 1 }
    try { Invoke-WebRequest -Uri "http://127.0.0.1:$WebPort/flows/$id/response/content.data?token=$token" -OutFile $file -UseBasicParsing }
    catch { Die "could not read the response body" }
    try { Get-Content -Raw $file | ConvertFrom-Json | Out-Null }
    catch { $textFile = [IO.Path]::ChangeExtension($file, ".txt"); $createdMock = if (Test-Path $textFile) { 0 } else { 1 }; Move-Item -Force $file $textFile; $file = $textFile }
    & $python.Exe @($python.Prefix) -I (Join-Path $PSScriptRoot "addons\rules_cli.py") $RulesPath rules mock-set $Action "match=$Name" action=map_local "file=$file" "status=$status" "method=$method" "headers=$headers" "created_mock=$createdMock" | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Info "saved the real $method response ($status) to $file"
    Info "map_local rule '$Action' is ON - edit that file; every save applies to the next call"
    Info "turn off: ${Cli}.ps1 rules off $Action"
  }
  "android" {
    if ($All) {
      if ($Serial) { Die "android ${Action}: use -Serial or -All, not both" }
      if ($Action -notin @("on","off")) { Die "usage: ${Cli}.ps1 android on|off [-Serial SERIAL | -All]" }
      $adb = Find-Adb
      $devices = & $adb devices; Run "adb devices"
      $emulators = @($devices | Select-String '^(emulator-\d+)\s+device$' | ForEach-Object { $_.Matches[0].Groups[1].Value })
      if (-not $emulators.Count) { Die "no running emulator. Physical devices need a separate approval." }
      $failed = @()
      foreach ($emulator in $emulators) {   # every emulator gets its turn; any one not done fails the command (review R7)
        if ($ProxyOnly) { & $PSCommandPath android $Action -Serial $emulator -Project $Project -ProxyOnly }
        else { & $PSCommandPath android $Action -Serial $emulator -Project $Project }
        if ($LASTEXITCODE -ne 0) { $failed += $emulator }
      }
      if ($failed.Count) { Die "android ${Action}: not done on $($failed -join ' ') (see above)" }
      break
    }
    $adb = Find-Adb; $s = Pick-Serial $adb
    if ($Action -eq "on") { Ensure-Ca }
    # `off` must work even when mitmproxy or the CA file is gone
    $h = if (Test-Path $CaCer) { Get-CaHash } else { "" }; $dst = "/data/misc/user/0/cacerts-added/$h.0"
    & $adb -s $s root *> $null; Start-Sleep 2
    & $adb -s $s wait-for-device; Run "wait for emulator"
    $uid = ((& $adb -s $s shell id -u) -replace "`r","").Trim(); Run "read emulator uid"
    $root = $uid -eq "0"
    if ($Action -eq "on") {
      if ($root) {
        & $adb -s $s push $CaPem "/data/local/tmp/$h.0" | Out-Null; Run "push CA"
        & $adb -s $s shell "mkdir -p /data/misc/user/0/cacerts-added && cp /data/local/tmp/$h.0 $dst && chmod 644 $dst && chown system:system $dst && rm /data/local/tmp/$h.0"; Run "install CA"
        Add-CaHistory $h
        Info "${s}: CA installed in user store ($h.0)"
      } else {
        & $adb -s $s push $CaCer /sdcard/Download/proxy-ca.crt | Out-Null; Run "push CA (proxy NOT enabled)"
        Add-CaHistory $h
        Info "$s is a Google Play image (no adb root). CA pushed to Downloads. On the emulator:"
        Info "  Settings > Security > More security > Encryption & credentials > Install a certificate"
        Info "  > CA certificate > Install anyway > Downloads > proxy-ca.crt"
        Info "  (or use a 'Google APIs' AVD without Play Store and this step is automatic)"
        if (-not $ProxyOnly) {
          # review R7: with the proxy on and no trusted CA every HTTPS call fails, so the proxy waits for the CA
          Info "${s}: NOT DONE - the CA cannot be verified from Windows, so the proxy was left off."
          Info "  After installing it as above, run: .\${Cli}.ps1 android on -Serial $s -ProxyOnly"
          exit 2
        }
        Info "${s}: -ProxyOnly: proxy on (you installed the CA by hand)"
      }
      & $adb -s $s shell settings put global http_proxy "10.0.2.2:$Port"; Run "set proxy"
      $now = ((& $adb -s $s shell settings get global http_proxy) -replace "`r","").Trim(); Run "verify proxy"
      if ($now -ne "10.0.2.2:$Port") { Die "${s}: setting the proxy failed" }
      Set-AndroidProxyMark $adb $s $true
      Info "${s}: proxy -> 10.0.2.2:$Port. Run a *Debug* variant (release builds pin TLS)."
      if (-not (Port-Owner $Port)) { Info "WARNING: nothing listens on :$Port yet - run '.\${Cli}.ps1 start' or the emulator has no internet" }
    } elseif ($Action -eq "off") {
      & $adb -s $s shell settings put global http_proxy :0; Run "clear proxy"
      $now = ((& $adb -s $s shell settings get global http_proxy) -replace "`r","").Trim(); Run "verify cleared proxy"
      if (-not $now) { Die "${s}: empty proxy result - could not verify it was cleared" }
      if ($now -notin @(":0", "null")) { Die "${s}: proxy still set ($now)" }
      Set-AndroidProxyMark $adb $s $false
      Info "${s}: proxy cleared"
      if ($root) {
        # F-07: also the CAs of earlier regenerations (state root ca-history, shared with the bash edition)
        $hashes = @(@($h) + @(Get-CaHistoryHashes) | Where-Object { $_ -match '^[0-9a-fA-F]+$' } | Select-Object -Unique)
        if (-not $hashes.Count) { Die "${s}: no CA on record and the CA file is gone, cannot tell which cert to remove - check /data/misc/user/0/cacerts-added by hand" }
        # every mitmproxy CA has the same file name: remove a file only when its SHA-256 is recorded (review R3)
        $want = Get-CaHistoryShas; $removed = 0; $kept = @()
        foreach ($f in @($hashes | ForEach-Object { "/data/misc/user/0/cacerts-added/$_.0" })) {
          & $adb -s $s shell "[ -e $f ]"; if ($LASTEXITCODE -ne 0) { continue }
          $tmp = [IO.Path]::GetTempFileName(); $sha = ""
          try {
            ((& $adb -s $s shell cat $f) -join "`n") -replace "`r","" | Set-Content -LiteralPath $tmp -Encoding ascii
            $sha = Get-CertSha256 $tmp
          } catch { $sha = "" } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
          if ($sha -and ($want -contains $sha)) {
            & $adb -s $s shell "rm -f $f"; Run "remove CA"
            & $adb -s $s shell "[ ! -e $f ]"; if ($LASTEXITCODE -ne 0) { Die "${s}: CA still present at $f" }
            $removed++
          } else { $kept += $f }
        }
        & $adb -s $s shell rm -f /sdcard/Download/proxy-ca.crt
        Info "${s}: removed $removed CA file(s) of this workstation ($($hashes.Count) recorded CA(s) checked)"
        if ($kept.Count) { Info "${s}: left in place, not this workstation's CA (another mitmproxy install?): $($kept -join ' ')" }
      } else {
        & $adb -s $s shell rm -f /sdcard/Download/proxy-ca.crt
        Info "${s}: remove the CA by hand: Encryption & credentials > Trusted credentials > User > mitmproxy > Uninstall"
      }
    } else { Die "usage: ${Cli}.ps1 android on|off [-Serial SERIAL]" }
  }
  "setup" {
    Info "iOS: unavailable on Windows (there is no iOS Simulator)"
    & $PSCommandPath android on -All -Project $Project
    exit $LASTEXITCODE
  }
  "net-reset" {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $cur = Get-ItemProperty $key
    Info "user proxy: enabled=$($cur.ProxyEnable) server=$($cur.ProxyServer)"
    $whLines = @(netsh winhttp show proxy); Run "read WinHTTP proxy"
    $wh = $whLines -join " "
    Info "winhttp: $wh"
    $userStale = $cur.ProxyEnable -eq 1 -and (Test-StaleLocalProxy $cur.ProxyServer)
    if ($cur.ProxyEnable -eq 1 -and -not $userStale) {
      Info "user proxy left alone (not a local leftover)"
    } elseif ($userStale) {
      Info "user proxy does not answer; left alone because its origin cannot be proved"
    }
    $whLine = $whLines | Where-Object { $_ -match '^\s*Proxy Server\(s\)\s*:' } | Select-Object -First 1
    $whSpec = if ($whLine) { ($whLine -replace '^\s*Proxy Server\(s\)\s*:\s*', '').Trim() } else { "" }
    $winHttpStale = $whSpec -and (Test-StaleLocalProxy $whSpec)
    if ($whSpec -and -not $winHttpStale) {
      Info "WinHTTP proxy left alone (not a local leftover)"
    } elseif ($winHttpStale) {
      Info "WinHTTP proxy does not answer; left alone because its origin cannot be proved"
    }
    if ($DryRun) { Info "dry run: nothing changed" }
    elseif (-not $userStale -and -not $winHttpStale) { Info "no stale local proxy found" }
    else { Info "unanswered local proxy settings were left alone; clear them manually after checking ownership" }
  }
  "doctor" {
    # Prefer the shared Python checker (same logic as macOS). Read-only.
    $pythonExe = $null
    $pyArgs = @()
    foreach ($cand in @("py","python3","python")) {
      $c = Get-Command $cand -ErrorAction SilentlyContinue
      if ($c) {
        $pythonExe = $c.Source
        if ($cand -eq "py") { $pyArgs = @("-3") }
        break
      }
    }
    $doctorPy = Join-Path $PSScriptRoot "addons\doctor.py"
    if ($pythonExe -and (Test-Path $doctorPy)) {
      $adbPath = (Get-Command adb -ErrorAction SilentlyContinue).Source
      $argv = @($doctorPy, "--project", $Project, "--rules", $RulesPath, "--confdir", $ConfDir,
                "--port", $Port, "--web-port", $WebPort, "--script-dir", (Join-Path $ProjectState "scripts"),
                "--upstream", (Get-Upstream))
      if ($adbPath) { $argv += @("--adb", $adbPath) }
      if ($Json)    { $argv += "--json" }
      if ($NoNet)   { $argv += "--no-net" }
      if ($AllowProfileNetwork) { $argv += "--allow-profile-network" }
      if ($FixSafe) { $argv += "--fix-safe" }
      if ($Yes)     { $argv += "--yes" }
      & $pythonExe @pyArgs @argv
      exit $LASTEXITCODE
    }
    # Reduced native subset when Python is unavailable.
    Write-Host "doctor (native subset — install Python for the full check)"
    $doctorExit = 0
    $mitm = Get-Command mitmdump -ErrorAction SilentlyContinue
    if ($mitm) {
      $v = (& $mitm.Source --version 2>&1 | Select-String -Pattern 'itmproxy:?\s*v?([0-9.]+)')
      $ver = if ($v) { $v.Matches[0].Groups[1].Value } else { "unknown" }
      $mark = if ($ver -eq $PinnedMitmproxy) { "ok" } else { $doctorExit = [Math]::Max($doctorExit, 1); "warn" }
      Write-Host ("  [{0}] mitmproxy {1} at {2}" -f $mark, $ver, $mitm.Source)
    } else {
      $doctorExit = 2
      Write-Host "  [error] mitmproxy not found (install the pinned $PinnedMitmproxy build from the internal mirror)"
    }
    foreach ($pp in @(@("proxy",$Port),@("web UI",$WebPort))) {
      $o = Port-Owner $pp[1]
      if ($o) { $doctorExit = [Math]::Max($doctorExit, 1); Write-Host ("  [warn] {0} port :{1} owned by {2}" -f $pp[0],$pp[1],$o) }
      else    { Write-Host ("  [ok] {0} port :{1} is free" -f $pp[0],$pp[1]) }
    }
    $cur = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    if ($cur.ProxyEnable -eq 1) {
      $stale = Test-StaleLocalProxy $cur.ProxyServer
      if ($stale) { $doctorExit = 2; Write-Host ("  [error] unanswered WinINET proxy {0} — inspect it in Windows proxy settings" -f $cur.ProxyServer) }
      else        { $doctorExit = [Math]::Max($doctorExit, 1); Write-Host ("  [warn] WinINET system proxy set: {0} (steals emulator traffic)" -f $cur.ProxyServer) }
    } else { Write-Host "  [ok] no WinINET system proxy" }
    $whLine = (netsh winhttp show proxy 2>$null | Select-String 'Proxy Server')
    if ($whLine) { Write-Host ("  [info] WinHTTP: {0}" -f ($whLine.ToString().Trim())) }
    $adb = Get-Command adb -ErrorAction SilentlyContinue
    if ($adb) {
      & adb devices | Select-String '^(emulator-\d+)\s+device$' | ForEach-Object {
        $e = $_.Matches[0].Groups[1].Value
        Write-Host ("  [info] android {0}: http_proxy={1}" -f $e, ((& adb -s $e shell settings get global http_proxy) -replace "`r",''))
      }
    } else { Write-Host "  [info] adb not found" }
    exit $doctorExit
  }
  "bug-report" {
    $pythonExe = $null
    $pyArgs = @()
    foreach ($cand in @("py","python3","python")) {
      $c = Get-Command $cand -ErrorAction SilentlyContinue
      if ($c) { $pythonExe = $c.Source; if ($cand -eq "py") { $pyArgs = @("-3") }; break }
    }
    if (-not $pythonExe) { Die "Python is required to create a bug report" }
    $argv = @((Join-Path $PSScriptRoot "addons\bug_report.py"), "--state-root", $StateRoot,
              "--project", $Project, "--rules", $RulesPath, "--confdir", $ConfDir,
              "--port", $Port, "--web-port", $WebPort, "--script-dir", (Join-Path $ProjectState "scripts"))
    $adbPath = (Get-Command adb -ErrorAction SilentlyContinue).Source
    if ($adbPath) { $argv += @("--adb", $adbPath) }
    if ($Output) { $argv += @("--output", $Output) }
    & $pythonExe @pyArgs @argv
    exit $LASTEXITCODE
  }
  "status" {
    Ensure-Rules
    Write-Host "project: $Project ($($ProjectConfig.label))"
    Write-Host "upstream proxy: $(Get-Upstream)"
    $statusCfg = Read-RulesConfig
    $statusTls = Get-Tls $statusCfg
    Write-Host ("TLS decryption: {0}{1}" -f $statusTls.mode, $(if ($statusTls.mode -eq "all") { " (every host)" } else { " ($(@($statusTls[$statusTls.mode]).Count) host pattern(s))" }))
    if ($statusCfg.no_cache -eq $true) { Write-Host "No caching: on" }
    if (@($ProjectConfig.android_packages).Count) { Write-Host "project Android packages: $(@($ProjectConfig.android_packages) -join ', ')" }
    if (@($ProjectConfig.ios_bundle_ids).Count) { Write-Host "project iOS bundle IDs: $(@($ProjectConfig.ios_bundle_ids) -join ', ')" }
    $o = Port-Owner $Port;    Write-Host "proxy :$Port     $(if ($o) { $o } else { 'not listening' })"
    $w = Port-Owner $WebPort; Write-Host "web UI :$WebPort   $(if ($w) { $w } else { 'not listening' })"
    $cur = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    Write-Host "windows system proxy: $(if ($cur.ProxyEnable -eq 1) { $cur.ProxyServer } else { 'off' })"
    $adb = Get-Command adb -ErrorAction SilentlyContinue
    if ($adb) {
      & adb devices | Select-String '^(emulator-\d+)\s+device$' | ForEach-Object {
        $e = $_.Matches[0].Groups[1].Value
        Write-Host "android ${e}: http_proxy=$((& adb -s $e shell settings get global http_proxy) -replace "`r",'')"
      }
    }
    $cfg = Read-RulesConfig
    if (@($cfg.scripts | Where-Object { $_.enabled -ne $false -and $_.lang -eq "js" }).Count) {
      $nodeOverride = [Environment]::GetEnvironmentVariable("${EnvPrefix}_NODE")
      $nodeCandidates = @($nodeOverride, (Join-Path $HOME ".nvm\versions\node\current\bin\node.exe"),
                          "C:\Program Files\nodejs\node.exe", "C:\Program Files (x86)\nodejs\node.exe")
      if ($env:NVM_HOME) { $nodeCandidates += (Join-Path $env:NVM_HOME "node.exe") }
      $nodeFound = Get-Command node.exe -ErrorAction SilentlyContinue
      if (-not $nodeFound -and -not ($nodeCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1)) {
        Write-Host "scripts: Node.js not installed (winget install OpenJS.NodeJS or https://nodejs.org) - JS scripts disabled (Python scripts still work)"
      }
    }
  }
  "browser" {
    if ($List) { foreach ($id in $BrowserNames.Keys) { if (Find-Browser $id) { Write-Output "$id`t$($BrowserNames[$id])" } }; break }
    if ($Current) { Die "browser: -Current is not available on Windows yet; copy the URL from the address bar instead" }
    $url = "about:blank"
    if ($Action) {
      $url = $Action
      # a bare host (or host:port) gets https://; any other scheme (javascript:, file:, data:) is refused
      if ($url -notmatch '://' -and $url -notmatch '^[A-Za-z][A-Za-z0-9+.-]*:([^0-9]|$)') { $url = "https://$url" }
      if ($url -notmatch '^https?://\S+$') { Die "browser: '$Action' is not an http(s) URL" }
    }
    $id = $Browser
    if (-not $id) { $id = @($BrowserNames.Keys | Where-Object { Find-Browser $_ } | Select-Object -First 1)[0] }
    if (-not $id) { Die "browser: no Chrome, Edge, Chromium or Brave found (Firefox is not supported yet)" }
    $bin = Find-Browser $id
    if (-not $bin) { Die "browser: $id is not installed" }
    $owner = @(Listening-Pids @([int]$Port))
    if (-not $owner.Count) { Die "$ProductName is not running on :$Port - ${Cli}.ps1 start" }
    if (-not (Test-OurMitmweb ([int]$owner[0]))) { Die "port $Port is held by another program, not by this $ProductName - the browser would not be captured" }
    Ensure-Ca
    $spki = Get-CaSpki
    if ($Fresh) {
      # under the state root (private), not %TEMP%; leftovers of earlier runs go now, except one a browser still runs on
      $browserRoot = Join-Path $StateRoot "browser"
      New-Item -ItemType Directory -Force -Path $browserRoot | Out-Null
      if (-not $IsWindows -and $PSVersionTable.PSEdition -ne "Desktop") { & chmod 700 $browserRoot }
      $running = ""
      if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        $running = (@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.CommandLine }) -join "`n")
      } else {
        $running = (@(& ps -axo command= 2>$null) -join "`n")
      }
      $leftovers = @(Get-ChildItem -LiteralPath $browserRoot -Directory -Filter "tmp-*" -ErrorAction SilentlyContinue) +
                   @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter "$Cli-browser.*" -ErrorAction SilentlyContinue)
      foreach ($old in $leftovers) {
        if ($running.Contains("--user-data-dir=$($old.FullName)")) { continue }
        Remove-Item -LiteralPath $old.FullName -Recurse -Force -ErrorAction SilentlyContinue
      }
      $browserProfile = Join-Path $browserRoot ("tmp-" + [IO.Path]::GetRandomFileName().Replace(".", ""))
      New-Item -ItemType Directory -Force -Path $browserProfile | Out-Null
      if (-not $IsWindows -and $PSVersionTable.PSEdition -ne "Desktop") { & chmod 700 $browserProfile }
    } else {
      $browserProfile = Join-Path (Join-Path $StateRoot "browser") $id
      New-Item -ItemType Directory -Force -Path $browserProfile | Out-Null     # under the state root, private (Protect-StateRoot)
      if (-not $IsWindows -and $PSVersionTable.PSEdition -ne "Desktop") { & chmod 700 (Join-Path $StateRoot "browser") $browserProfile }
    }
    # Web apps on localhost go through Rivis only when this Rivis allows them (start --allow-private-hosts): by
    # default it refuses private destinations, so the browser reaches localhost directly (same as the bash CLI).
    # The UI itself always stays direct (it would record itself).
    $bypass = "127.0.0.1:$WebPort;localhost:$WebPort"; $loopback = $false
    try {
      $wc = New-Object System.Net.WebClient; $wc.Proxy = $null
      $token = (Get-Content -Raw -LiteralPath $TokenPath).Trim()
      $allowed = [string](($wc.DownloadString("http://127.0.0.1:$WebPort/options?token=$token") | ConvertFrom-Json).proxy_private_hosts.value)
      if ($allowed -and @("localhost","127.0.0.1" | Where-Object { $_ -notmatch "^(?:$allowed)$" }).Count -eq 0) {
        $bypass = "<-loopback>;$bypass"; $loopback = $true
      }
    } catch { }
    $flags = @("--user-data-dir=$browserProfile", "--proxy-server=127.0.0.1:$Port",
               "--proxy-bypass-list=$bypass",
               "--ignore-certificate-errors-spki-list=$spki", "--use-mock-keychain",
               "--no-first-run", "--no-default-browser-check", "--disable-sync", $url)
    Start-Process -FilePath $bin -ArgumentList (($flags | ForEach-Object { Quote-Arg $_ }) -join " ") | Out-Null
    Info "opened $id with its own $ProductName profile -> proxy 127.0.0.1:$Port"
    Info "profile $browserProfile$(if ($Fresh) { ' (temporary)' })"
    Info "your normal browser, the system proxy and the certificate store are not touched; close that window when done"
    if (-not $loopback -and $url -match '^https?://(localhost|127\.0\.0\.1)([:/]|$)') {
      Info "localhost opens directly, not through $ProductName (it blocks private addresses unless told otherwise). To capture it:"
      Info "  start $ProductName with --allow-private-hosts '^(localhost|127\.0\.0\.1)$', then run this again"
    }
  }
  "cert" {
    Ensure-Ca
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CaCer
    Write-Host "CA:        $CaPem"
    # SHA256 by hand: GetCertHashString(HashAlgorithmName) needs .NET 4.8, not always under PS 5.1
    $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
    Write-Host "sha256:    $(($sha | ForEach-Object { $_.ToString('X2') }) -join '')"
    Write-Host "android:   $(Get-CaHash).0"
    Write-Host "expires:   $($cert.NotAfter)"
  }
  default {
    Write-Usage
  }
}
