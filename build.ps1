# VanGuard build script — PowerShell
#
# Builds vanguard.exe with version, build date, and short commit hash injected
# via -ldflags so the binary self-identifies. Requires CGO (SQLite case DB).
# Uses -trimpath to strip local filesystem paths from the binary.
#
# Usage:
#   ./build.ps1                  # build with default version
#   ./build.ps1 -Version 1.2.3   # build with explicit version

[CmdletBinding()]
param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

$Date = Get-Date -Format "yyyy-MM-dd"

$Commit = "unknown"
try {
    $rev = git rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $rev) {
        $Commit = $rev.Trim()
    }
} catch {
    # Not a git repo, or git missing — keep "unknown".
}

$env:CGO_ENABLED = 1

Write-Host "Building VanGuard v$Version ($Date, $Commit)..." -ForegroundColor Cyan

$ldflags = "-X main.version=$Version -X main.buildDate=$Date -X main.commit=$Commit"
go build -trimpath -ldflags "$ldflags" -o vanguard.exe ./cmd/vanguard/

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful: vanguard.exe" -ForegroundColor Green
    Write-Host "  Version: $Version" -ForegroundColor Gray
    Write-Host "  Date:    $Date" -ForegroundColor Gray
    Write-Host "  Commit:  $Commit" -ForegroundColor Gray
} else {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}
