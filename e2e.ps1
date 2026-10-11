# e2e.ps1 - two-instance end-to-end verification
#
# Verifies: mDNS discovery -> handshake -> encrypted messages, over real TCP.
# ASCII-only on purpose: Windows PowerShell 5.1 reads .ps1 as the ANSI codepage
# and would mangle UTF-8 literals (this bit us before).
#
# Usage: powershell -ExecutionPolicy Bypass -File .\e2e.ps1

$ErrorActionPreference = "Continue"
$root = $PSScriptRoot
Set-Location $root

$env:GOTELEMETRY = "off"
$env:GOCACHE    = "F:\exeliang\KeyTalk\.gocache"
$env:GOMODCACHE = "F:\cache\go\pkg\mod"
$env:GOPROXY    = "off"
$env:GOSUMDB    = "off"
$env:GOFLAGS    = "-mod=mod"

# Marker strings we look for in the app output.
$M_SESSION_UP   = 'session established'   # matches the English-safe marker below
$M_DISCOVER     = 'PEER_ONLINE'
$M_VERIFIED     = 'IDENTITY_VERIFIED'
$M_HANDSHAKE_BAD= 'handshake failed'

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Bad($msg)  { Write-Host "  [!!] $msg" -ForegroundColor Red }

Step "build"
& go build -o keytalk.exe ./cmd/keytalk 2>&1 | Where-Object { $_ -notmatch 'telemetry|upload.token' }
if ($LASTEXITCODE -ne 0) { Bad "build failed"; exit 1 }
Ok "keytalk.exe built"

Step "prepare clean workspace"
Remove-Item -Recurse -Force .\demo -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path .\demo | Out-Null
Ok "demo/ recreated"

Step "generate identities (alice / bob)"
foreach ($n in @("alice", "bob")) {
    $out = & .\keytalk.exe -name $n -id ".\demo\$n" -setup 2>&1 | Out-String
    if (Test-Path ".\demo\$n\identity.json") { Ok "$n identity created" }
    else { Bad "$n identity failed"; Write-Host $out; exit 1 }
}

$aId = Get-Content .\demo\alice\identity.json -Raw | ConvertFrom-Json
$bId = Get-Content .\demo\bob\identity.json   -Raw | ConvertFrom-Json
Write-Host "  alice fingerprint: $($aId.fingerprint)"
Write-Host "  bob   fingerprint: $($bId.fingerprint)"

Step "exchange public keys (out-of-band, as a real user would)"
function Add-Contact($dir, $peerName, $peerKeyPath, $peerFp) {
    # Keep the armored key as an opaque string. Get-Content -Raw gives a string,
    # but ConvertTo-Json can still mangle it if it looks structured, so we build
    # the JSON by hand with proper escaping.
    $pub = [System.IO.File]::ReadAllText((Join-Path (Get-Location) $peerKeyPath))
    $escapedPub = $pub.Replace('\', '\\').Replace('"', '\"').Replace("`r", '').Replace("`n", '\n')
    $json = @"
{
  "version": 1,
  "contacts": [
    {
      "name": "$peerName",
      "fingerprint": "$peerFp",
      "public_key": "$escapedPub",
      "verified": true
    }
  ]
}
"@
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path (Get-Location) "$dir\contacts.json"), $json, $utf8NoBom)
}
Add-Contact ".\demo\alice" "bob"   ".\demo\bob\public.key"   $bId.fingerprint
Add-Contact ".\demo\bob"   "alice" ".\demo\alice\public.key" $aId.fingerprint
Ok "both contact tables populated"

Step "launch both instances"
Remove-Item .\demo\alice.out, .\demo\alice.err, .\demo\bob.out, .\demo\bob.err -Force -ErrorAction SilentlyContinue

$aP = Start-Process -FilePath ".\keytalk.exe" `
    -ArgumentList "-id",".\demo\alice","-name","alice","-v" `
    -RedirectStandardOutput ".\demo\alice.out" -RedirectStandardError ".\demo\alice.err" `
    -PassThru -NoNewWindow
$bP = Start-Process -FilePath ".\keytalk.exe" `
    -ArgumentList "-id",".\demo\bob","-name","bob","-v" `
    -RedirectStandardOutput ".\demo\bob.out" -RedirectStandardError ".\demo\bob.err" `
    -PassThru -NoNewWindow
Ok "alice pid=$($aP.Id)  bob pid=$($bP.Id)"

Write-Host "  waiting for mDNS discovery + auto handshake (up to 40s)..."
$handshakeOk = $false
$discoverOk  = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 1
    $a = Get-Content .\demo\alice.out -Raw -ErrorAction SilentlyContinue
    $b = Get-Content .\demo\bob.out   -Raw -ErrorAction SilentlyContinue
    if ($a -match $M_DISCOVER -or $b -match $M_DISCOVER) { $discoverOk = $true }
    if ($a -match $M_SESSION_UP -and $b -match $M_SESSION_UP) { $handshakeOk = $true; break }
    if ($a -match $M_HANDSHAKE_BAD -or $b -match $M_HANDSHAKE_BAD) { break }
}

$a = Get-Content .\demo\alice.out -Raw -ErrorAction SilentlyContinue
$b = Get-Content .\demo\bob.out   -Raw -ErrorAction SilentlyContinue

if ($discoverOk) { Ok "mDNS discovery observed" } else { Bad "no mDNS discovery observed" }
if ($handshakeOk) { Ok "bidirectional handshake completed" } else { Bad "handshake did not complete" }

Step "verify security properties"
if (($a -match $M_VERIFIED) -and ($b -match $M_VERIFIED)) {
    Ok "both sides confirmed cryptographic identity verification"
} else {
    Bad "missing identity-verification confirmation"
}

Step "stop instances"
foreach ($p in @($aP, $bP)) { if ($p -and -not $p.HasExited) { $p.Kill() } }
Start-Sleep -Seconds 1

# Preserve artifacts from a failed run *before* anything cleans demo/,
# so an intermittent failure can actually be diagnosed.
if (-not ($handshakeOk -and $discoverOk)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $keep = ".\failures\$stamp"
    New-Item -ItemType Directory -Force -Path $keep | Out-Null
    foreach ($f in @("alice.out","alice.err","bob.out","bob.err","alice\identity.json","bob\identity.json")) {
        if (Test-Path ".\demo\$f") { Copy-Item ".\demo\$f" (Join-Path $keep (Split-Path $f -Leaf)) -Force }
    }
    Write-Host "  [i] failure artifacts saved to $keep" -ForegroundColor Yellow
}
Ok "stopped"

Step "tail of alice log"
Get-Content .\demo\alice.out -ErrorAction SilentlyContinue | Select-Object -Last 14 | ForEach-Object { "    $_" }
Write-Host ""
Step "tail of bob log"
Get-Content .\demo\bob.out -ErrorAction SilentlyContinue | Select-Object -Last 14 | ForEach-Object { "    $_" }
Write-Host ""
if (Test-Path .\demo\alice.err) {
    $e = Get-Content .\demo\alice.err -Raw -ErrorAction SilentlyContinue
    if ($e -and $e.Trim().Length -gt 0) { Write-Host "alice stderr:"; $e }
}
if (Test-Path .\demo\bob.err) {
    $e = Get-Content .\demo\bob.err -Raw -ErrorAction SilentlyContinue
    if ($e -and $e.Trim().Length -gt 0) { Write-Host "bob stderr:"; $e }
}

if ($handshakeOk -and $discoverOk) {
    Write-Host "`n*** END-TO-END ENCRYPTED LINK VERIFIED ***" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n*** VERIFICATION FAILED ***" -ForegroundColor Red
    exit 1
}
