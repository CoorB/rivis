<#
.SYNOPSIS
  One-step installer for Windows (PowerShell 5.1). User-scope only: no admin, no system proxy, 127.0.0.1 only.
.DESCRIPTION
  install.ps1 [-DryRun] [-FromMirror URL] [-MitmproxyZip PATH] [-ToolTarball PATH] [-AllowOfficial] [-NoPath]
  install.ps1 -Uninstall [-DryRun]

  mitmproxy source, in priority order (the pinned SHA-256 in mirror.conf is verified in EVERY case; mismatch = refuse):
    1. -FromMirror URL (or MIRROR_BASE_URL in mirror.conf once IT publishes it)
    2. -MitmproxyZip PATH
    3. the official URL, only with -AllowOfficial
  A mitmdump of the pinned version already on PATH is reused.
  Windows has no iOS Simulator: only the Android emulator path (adb from the Android SDK) and plain proxying apply.
  Uninstall removes our files and the PATH entry; it keeps the state dir and the CA.
#>
[CmdletBinding()]
param(
  [switch]$DryRun,
  [switch]$Uninstall,
  [string]$FromMirror = "",
  [string]$MitmproxyZip = "",
  [string]$ToolTarball = "",
  [switch]$AllowOfficial,
  [switch]$NoPath
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

function Info($m) { Write-Host ("* " + $m) }
function Warn($m) { Write-Host ("!! " + $m) -ForegroundColor Yellow }
function Die($m)  { Write-Host ("install: " + $m) -ForegroundColor Red; exit 1 }

$Here = $PSScriptRoot
$SrcRoot = Split-Path -Parent $Here
$ConfFile = Join-Path $Here "mirror.conf"

function Get-Conf([string]$key) {
  if (-not (Test-Path $ConfFile)) { Die "missing $ConfFile" }
  foreach ($l in Get-Content $ConfFile) {
    if ($l -match "^$([regex]::Escape($key))=(.*)$") { return $Matches[1].Trim() }
  }
  return ""
}

# ---- identity (never hardcode the product name) ---------------------------------------------------------------
$ProductJson = $null
foreach ($c in @((Join-Path $Here "product.json"), (Join-Path $SrcRoot "product.json"))) { if (Test-Path $c) { $ProductJson = $c; break } }
if (-not $ProductJson) {
  $hit = Get-ChildItem (Join-Path $env:LOCALAPPDATA "*\current\product.json") -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($hit) { $ProductJson = $hit.FullName }
}
if (-not $ProductJson) { Die "cannot find product.json (run from a checkout)" }
$Product = Get-Content -Raw $ProductJson | ConvertFrom-Json
$Cli = $Product.cli; $Name = $Product.name; $Prefix = $Product.env_prefix
$VerFile = Join-Path $Here "VERSION"
$ToolVersion = if (Test-Path $VerFile) { (Get-Content -Raw $VerFile).Trim() } else { "unknown" }
$MitmVersion = Get-Conf "MITMPROXY_VERSION"

$Root     = Join-Path $env:LOCALAPPDATA $Cli
$BinDir   = Join-Path $Root "bin"
$MitmDir  = Join-Path $Root "mitmproxy-$MitmVersion"
$ToolDir  = Join-Path $Root "tool-$ToolVersion"
$Current  = Join-Path $Root "current"
$Receipt  = Join-Path $Root "install-receipt.txt"
$ConfDir  = Join-Path $HOME ".mitmproxy"
$envConf = [Environment]::GetEnvironmentVariable("${Prefix}_CONFDIR")
if ($envConf) { $ConfDir = $envConf }
$StateDir = $Product.state_dir -replace '^~', $HOME
$CaPem    = Join-Path $ConfDir "mitmproxy-ca-cert.pem"

function Do-It([string]$what, [scriptblock]$block) {
  if ($DryRun) { Write-Host "  [dry-run] $what" } else { & $block }
}

function Get-UserPath { [Environment]::GetEnvironmentVariable("Path", "User") }
function Path-Has([string]$dir) {
  foreach ($p in ((Get-UserPath) -split ";")) { if ($p.TrimEnd("\") -ieq $dir.TrimEnd("\")) { return $true } }
  return $false
}
function Remove-Junction([string]$path) {
  if (Test-Path $path) {
    & cmd.exe /c rmdir "$path" | Out-Null
    if ($LASTEXITCODE) { Die "cannot remove junction $path" }
  }
}

# ---- uninstall ------------------------------------------------------------------------------------------------
if ($Uninstall) {
  Info "uninstall $Name ($Cli) - plan:"
  $byUs = (Test-Path $Receipt) -and ((Get-Content $Receipt) -contains "mitmproxy=installed-by-us")
  if ($byUs) { Do-It "remove $MitmDir" { Remove-Item -Recurse -Force $MitmDir -ErrorAction SilentlyContinue } }
  else { Info "mitmproxy was not installed by us (or no receipt) - left alone" }
  Get-ChildItem $Root -Directory -Filter "tool-*" -ErrorAction SilentlyContinue | ForEach-Object {
    $d = $_.FullName; Do-It "remove $d" { Remove-Item -Recurse -Force $d }
  }
  Do-It "remove launcher and current link" {
    Remove-Item -Force (Join-Path $BinDir "$Cli.cmd") -ErrorAction SilentlyContinue
    Remove-Junction $Current
    Remove-Item -Force $Receipt -ErrorAction SilentlyContinue
  }
  if (Path-Has $BinDir) {
    Do-It "remove $BinDir from the user PATH" {
      $new = ((Get-UserPath) -split ";" | Where-Object { $_ -and ($_.TrimEnd("\") -ine $BinDir.TrimEnd("\")) }) -join ";"
      [Environment]::SetEnvironmentVariable("Path", $new, "User")
    }
  }
  if (-not $DryRun) {
    Remove-Item $BinDir -ErrorAction SilentlyContinue
    if ((Test-Path $Root) -and -not (Get-ChildItem $Root -Force -ErrorAction SilentlyContinue)) { Remove-Item $Root }
  }
  Write-Host ""
  Info "kept (your data): state dir $StateDir and the CA in $ConfDir"
  Write-Host "  To remove them too: Remove-Item -Recurse '$StateDir'  (first run '$Cli android off' to remove the CA from emulators)"
  exit 0
}

# ---- plan -----------------------------------------------------------------------------------------------------
if (-not [Environment]::Is64BitOperatingSystem) { Die "64-bit Windows is required" }
$MFile = Get-Conf "MITMPROXY_FILE_WINDOWS_X86_64"
$MSha  = Get-Conf "MITMPROXY_SHA256_WINDOWS_X86_64"
$TSha  = Get-Conf "TOOL_SHA256"
$Mirror = if ($FromMirror) { $FromMirror } else { Get-Conf "MIRROR_BASE_URL" }
$Mirror = $Mirror.TrimEnd("/")

function Get-MitmVersion([string]$exe) {
  try { $o = & $exe --version 2>$null; foreach ($l in $o) { if ($l -match "^Mitmproxy:\s*(\S+)") { return $Matches[1] } } } catch {}
  return ""
}
$Reuse = $null
$cands = @((Join-Path $MitmDir "mitmdump.exe"))
$onPath = Get-Command mitmdump -ErrorAction SilentlyContinue
if ($onPath) { $cands += $onPath.Source }
# F-10: our own copy was hash-verified at install; any other mitmdump.exe needs a valid Authenticode signature
# whose signer matches MITMPROXY_WINDOWS_SIGNER in mirror.conf (empty = never reuse an external copy).
$Signer = Get-Conf "MITMPROXY_WINDOWS_SIGNER"
function Test-MitmSigned([string]$exe) {
  if (-not $Signer) { return $false }
  try { $sig = Get-AuthenticodeSignature -FilePath $exe } catch { return $false }
  return ($sig.Status -eq "Valid") -and ($sig.SignerCertificate.Subject -like "*$Signer*")
}
foreach ($c in $cands) {
  if (-not (Test-Path $c) -or (Get-MitmVersion $c) -ne $MitmVersion) { continue }
  $own = $c.StartsWith($MitmDir + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
  if (-not $own -and -not (Test-MitmSigned $c)) { Info "not reusing ${c}: not verifiably signed by mitmproxy"; continue }
  $Reuse = $c; break
}

Info "$Name ($Cli) installer - tool $ToolVersion, mitmproxy pinned $MitmVersion"
if ($DryRun) { Info "DRY RUN - nothing below will be changed" }
$MUrl = $null
if ($Reuse) { Info "plan: mitmproxy $MitmVersion already present at $Reuse - reuse (no download)" }
else {
  if ($Mirror)            { $MUrl = "$Mirror/mitmproxy/$MitmVersion/$MFile"; $From = "internal mirror" }
  elseif ($MitmproxyZip)  { $From = "local zip $MitmproxyZip" }
  elseif ($AllowOfficial) { $MUrl = "https://downloads.mitmproxy.org/$MitmVersion/$MFile"; $From = "official site (explicitly allowed)" }
  else { Die "no internal mirror or local mitmproxy zip; pass -AllowOfficial to explicitly permit downloads.mitmproxy.org" }
  Info "plan: install mitmproxy $MitmVersion from $From -> $MitmDir"
  if ($MUrl) { Info "      url    $MUrl" }
  if ($MSha) { Info "      sha256 $MSha (verified before use)" }
  else { Warn "no pinned SHA-256 for the Windows zip in mirror.conf yet - the installer will refuse until IT fills MITMPROXY_SHA256_WINDOWS_X86_64" }
  if ($From -like "official site*") { Warn "using the public official site by explicit request" }
}
if ($ToolTarball) { $TFrom = "tarball $ToolTarball" }
elseif (Test-Path (Join-Path $SrcRoot "$Cli.ps1")) { $TFrom = "this checkout ($SrcRoot)" }
elseif ($Mirror) { $TFrom = "mirror $Mirror/$Cli/$Cli-$ToolVersion.tar.gz" }
else { Die "no tool source: run from a checkout, or pass -ToolTarball / -FromMirror" }
Info "plan: install tool from $TFrom -> $ToolDir"
Info "plan: launcher $(Join-Path $BinDir "$Cli.cmd") (puts the pinned mitmproxy first on PATH for the tool only)"
if ($NoPath) { Info "plan: no PATH change (-NoPath)" }
elseif (Path-Has $BinDir) { Info "plan: $BinDir already on the user PATH" }
else { Info "plan: add $BinDir to the USER PATH (no admin)" }
if (Test-Path $CaPem) { Info "plan: CA exists in $ConfDir - left untouched" }
else { Info "plan: generate the per-workstation CA in $ConfDir (mitmdump on 127.0.0.1, free port, stopped right after)" }
Info "note: Windows has no iOS Simulator - iOS capture is macOS-only. Android emulator capture is supported."
Info "no admin rights, no system proxy changes, nothing listens beyond 127.0.0.1"
if ($DryRun) { Write-Host ""; Info "dry run finished - nothing changed"; exit 0 }

# ---- helpers --------------------------------------------------------------------------------------------------
function Verify([string]$file, [string]$expected, [string]$label) {
  if (-not $expected) { Die "$label`: no pinned SHA-256 in mirror.conf - refusing to use an unverified file" }
  $got = (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLower()
  if ($got -ne $expected.ToLower()) { Die "$label`: SHA-256 MISMATCH - refusing.`n   expected $expected`n   got      $got" }
  Info "$label`: sha256 OK"
}
function Fetch([string]$url, [string]$dest) {
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
  } catch { Die "download failed: $url ($($_.Exception.Message)) - blocked by the web filter? use -FromMirror or a local file" }
}
function Free-Port {
  $l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0); $l.Start()
  $p = $l.LocalEndpoint.Port; $l.Stop(); return $p
}

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("rivis-inst-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  New-Item -ItemType Directory -Force -Path $Root, $BinDir | Out-Null

  # ---- 1. mitmproxy ----
  $MitmByUs = $false
  if ($Reuse) {
    $MitmBin = Split-Path -Parent $Reuse
    $MitmByUs = $Reuse.StartsWith($MitmDir + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    if (-not $MitmByUs) { Info "reusing external mitmproxy: Authenticode signature verified ($Signer)" }
    Info "reusing mitmproxy $MitmVersion at $MitmBin"
  }
  else {
    if ($MUrl) { $zip = Join-Path $Tmp "mitm.zip"; Fetch $MUrl $zip }
    else { if (-not (Test-Path $MitmproxyZip)) { Die "no such file: $MitmproxyZip" }; $zip = Join-Path $Tmp "mitm-local.zip"; Copy-Item $MitmproxyZip $zip }
    Verify $zip $MSha "mitmproxy zip"
    $x = Join-Path $Tmp "mitm-x"
    Expand-Archive -Path $zip -DestinationPath $x -Force
    $exe = Get-ChildItem $x -Recurse -Filter "mitmdump.exe" | Select-Object -First 1
    if (-not $exe) { Die "zip has no mitmdump.exe" }
    if (Test-Path $MitmDir) { Remove-Item -Recurse -Force $MitmDir }
    Move-Item $exe.DirectoryName $MitmDir
    Get-ChildItem $MitmDir -Recurse -File | Unblock-File
    if ((Get-MitmVersion (Join-Path $MitmDir "mitmdump.exe")) -ne $MitmVersion) { Die "installed binary does not report version $MitmVersion" }
    $MitmBin = $MitmDir; $MitmByUs = $true
    Info "installed mitmproxy $MitmVersion -> $MitmDir"
  }

  # ---- 2. tool ----
  $tx = Join-Path $Tmp "tool-x"; New-Item -ItemType Directory -Path $tx | Out-Null
  if ($ToolTarball) {
    if (-not (Test-Path $ToolTarball)) { Die "no such file: $ToolTarball" }
    $localTool = Join-Path $Tmp "tool-local.tar.gz"; Copy-Item $ToolTarball $localTool
    Verify $localTool $TSha "tool tarball"
    & tar.exe -xzf $localTool -C $tx --strip-components=1; if ($LASTEXITCODE) { Die "cannot extract tool tarball (tar.exe needs Windows 10 1803+)" }
  } elseif (Test-Path (Join-Path $SrcRoot "$Cli.ps1")) {
    Get-ChildItem $SrcRoot -Force | Where-Object { $_.Name -notin @("install", ".DS_Store") } | ForEach-Object {
      Copy-Item $_.FullName -Destination $tx -Recurse -Force
    }
  } else {
    $tt = Join-Path $Tmp "tool.tar.gz"; Fetch "$Mirror/$Cli/$Cli-$ToolVersion.tar.gz" $tt
    Verify $tt $TSha "tool tarball"
    & tar.exe -xzf $tt -C $tx --strip-components=1; if ($LASTEXITCODE) { Die "cannot extract tool tarball" }
  }
  if (-not (Test-Path (Join-Path $tx "$Cli.ps1"))) { Die "tool payload has no '$Cli.ps1' entry point" }
  if (Test-Path $ToolDir) { Remove-Item -Recurse -Force $ToolDir }
  Move-Item $tx $ToolDir
  Get-ChildItem $ToolDir -Recurse -File | Unblock-File
  Remove-Junction $Current
  # a junction needs no admin rights (a symlink does)
  & cmd.exe /c mklink /J "$Current" "$ToolDir" | Out-Null; if ($LASTEXITCODE) { Die "cannot create junction $Current" }
  Info "installed tool $ToolVersion -> $ToolDir"

  # ---- 3. launcher + PATH ----
  $launcher = Join-Path $BinDir "$Cli.cmd"
  if ((Test-Path $launcher) -and -not ((Get-Content -Raw $launcher) -match "generated by the installer")) {
    Die "$launcher exists and was not created by this installer - remove it, then re-run"
  }
  $lines = @("@echo off", "rem generated by the installer - do not edit; re-run install.ps1 to change")
  if ($MitmByUs) { $lines += "set `"PATH=$MitmBin;%PATH%`"" }
  $lines += "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Root\current\$Cli.ps1`" %*"
  Set-Content -Path $launcher -Value $lines -Encoding ASCII
  Info "launcher $launcher"
  if (-not $NoPath -and -not (Path-Has $BinDir)) {
    $cur = Get-UserPath
    [Environment]::SetEnvironmentVariable("Path", $(if ($cur) { "$cur;$BinDir" } else { $BinDir }), "User")
    Info "added $BinDir to the user PATH (open a new terminal to pick it up)"
  }
  @("version=$ToolVersion", "mitmproxy_version=$MitmVersion", $(if ($MitmByUs) { "mitmproxy=installed-by-us" } else { "mitmproxy=reused" })) |
    Set-Content -Path $Receipt -Encoding ASCII

  # ---- 4. CA ----
  $mitmdump = Join-Path $MitmBin "mitmdump.exe"
  if (Test-Path $CaPem) { Info "CA already present in $ConfDir - not modified" }
  else {
    Info "generating the per-workstation CA in $ConfDir"
    $p = Start-Process -FilePath $mitmdump -WindowStyle Hidden -PassThru `
         -ArgumentList @("--listen-host", "127.0.0.1", "--listen-port", (Free-Port), "--set", "confdir=`"$ConfDir`"")
    for ($i = 0; $i -lt 30 -and -not (Test-Path $CaPem); $i++) { Start-Sleep -Milliseconds 500 }
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
    if (-not (Test-Path $CaPem)) { Die "CA was not generated in $ConfDir" }
    Info "CA generated"
  }

  # ---- 5. Android emulator path ----
  $adb = $null
  $ac = Get-Command adb -ErrorAction SilentlyContinue
  if ($ac) { $adb = $ac.Source }
  else {
    foreach ($c in @((Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe"),
                     $(if ($env:ANDROID_HOME) { Join-Path $env:ANDROID_HOME "platform-tools\adb.exe" }),
                     $(if ($env:ANDROID_SDK_ROOT) { Join-Path $env:ANDROID_SDK_ROOT "platform-tools\adb.exe" }))) {
      if ($c -and (Test-Path $c)) { $adb = $c; break }
    }
  }

  # ---- 6. self-check ----
  Write-Host ""; Info "self-check"
  Write-Host "  tool       $Name $ToolVersion  ($Current)"
  Write-Host "  mitmproxy  $(Get-MitmVersion $mitmdump)  ($MitmBin)"
  $fp = ""
  try { $fp = (New-Object Security.Cryptography.X509Certificates.X509Certificate2($CaPem)).GetCertHashString("SHA256") } catch {}
  Write-Host "  CA sha256  $fp"
  if ($adb) { Write-Host "  adb        $adb" }
  else { Write-Host "  adb        NOT FOUND - install Android SDK platform-tools (or set ANDROID_HOME) before '$Cli android on'" }
  Write-Host "  iOS        not available on Windows (the iOS Simulator is macOS-only)"
  Write-Host ""; Info "next steps"
  Write-Host "  $Cli start          # open a new terminal first if PATH was just updated"
  Write-Host "  $Cli android on     # installs the CA + proxy in the Android emulator"
}
finally { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue }
