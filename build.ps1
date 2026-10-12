# Build KeyTalk into a single, double-clickable executable.
#
#   .\build.ps1              hybrid build (default)
#   .\build.ps1 -GuiOnly     no console window at all
#   .\build.ps1 -Clean       wipe dist\ first
#   .\build.ps1 -Run         build, then launch
#
# NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads .ps1
# files using the ANSI codepage, so non-ASCII text here would corrupt
# the script. (This project has already been bitten by that once.)

[CmdletBinding()]
param(
    [switch]$GuiOnly,
    [switch]$Clean,
    [switch]$Run
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

# A repo-local module/build cache takes priority when present, so the
# build works offline and never writes into a shared cache that may be
# read-only. Otherwise the ambient Go configuration is left untouched.
if (Test-Path (Join-Path $root ".gomodcache")) {
    $env:GOMODCACHE = Join-Path $root ".gomodcache"
}
if (Test-Path (Join-Path $root ".gocache")) {
    $env:GOCACHE = Join-Path $root ".gocache"
}
$env:GOTELEMETRY = "off"
if (-not $env:GOFLAGS) { $env:GOFLAGS = "-mod=mod" }

# Invoke-Native runs an external program and returns its exit code plus
# its combined output as plain text.
#
# Written this way because $ErrorActionPreference = "Stop" turns ANY
# native stderr write into a terminating error on PowerShell 7.4+,
# even when the program succeeded. KeyTalk deliberately writes a
# warning to stderr on first run (the private key is stored in
# plaintext), so without this the smoke test would fail on a
# perfectly healthy build.
function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments = @())

    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        # "$_" flattens ErrorRecords into readable text instead of
        # leaving .NET objects in the pipeline.
        $lines = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    return [pscustomobject]@{ Output = ($lines -join "`n"); Code = $code }
}

$dist = Join-Path $root "dist"
if ($Clean -and (Test-Path $dist)) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$exe = Join-Path $dist "keytalk.exe"

$goArgs = @("build", "-trimpath")
if ($GuiOnly) {
    # Windows GUI subsystem: the OS never creates a console window, so
    # there is no flash on launch. The cost is that stdout is detached,
    # which means this binary can no longer serve as a CLI tool.
    $goArgs += "-ldflags=-H=windowsgui"
    Write-Host "Mode : GUI only (no console window; not usable as a CLI)"
} else {
    Write-Host "Mode : hybrid (double-click opens the GUI; flags keep the CLI working)"
}

Write-Host "Build: $exe"
$goArgs += @("-o", $exe, "./cmd/keytalk")
$build = Invoke-Native "go" $goArgs
if ($build.Code -ne 0) {
    Write-Host $build.Output
    throw "go build failed with exit code $($build.Code)"
}
if (-not (Test-Path $exe)) { throw "go build reported success but produced no file" }

# Smoke test: prove the artifact actually runs, not merely that it
# linked. Skipped for -GuiOnly because stdout is detached in that build.
if (-not $GuiOnly) {
    Write-Host "Smoke: launching -setup in a scratch directory"
    $smoke = Join-Path $dist "_smoke"
    if (Test-Path $smoke) { Remove-Item -Recurse -Force $smoke }
    $r = Invoke-Native $exe @("-setup", "-name", "smoketest", "-id", $smoke)
    if ($r.Code -ne 0) {
        Write-Host $r.Output
        throw "smoke test: exit code $($r.Code)"
    }
    if ($r.Output -notmatch "SETUP_DONE") {
        Write-Host $r.Output
        throw "smoke test: no SETUP_DONE marker in output"
    }
    foreach ($f in @("identity.json", "public.key")) {
        if (-not (Test-Path (Join-Path $smoke $f))) {
            throw "smoke test: $f was not written"
        }
    }
    Remove-Item -Recurse -Force $smoke
    Write-Host "Smoke: OK (identity generated, keys written)"
}

$item = Get-Item $exe
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
$size = "{0:N2} MB" -f ($item.Length / 1MB)

Write-Host ""
Write-Host "Output : $($item.FullName)"
Write-Host "Size   : $size"
Write-Host "SHA256 : $hash"
Write-Host ""

if ($Run) {
    Write-Host "Launching (close the window to exit)..."
    $r = Invoke-Native $exe @()
    if ($r.Output.Trim() -ne "") { Write-Host $r.Output }
    if ($r.Code -ne 0) { throw "keytalk exited with code $($r.Code)" }
} else {
    Write-Host "Double-click it, or pass flags for the CLI (try -h)."
}
