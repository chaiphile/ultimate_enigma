<#
.SYNOPSIS
    Installs the optional code-analysis toolchain for Ultimate Enigma.

.DESCRIPTION
    Installs, idempotently, the external dev tools the app's code-analysis
    service can wrap: tree-sitter, ripgrep, clangd, semgrep,
    universal-ctags, rust-analyzer, and CodeQL.

    - ripgrep + clangd  -> winget
    - tree-sitter       -> npm (global)
    - semgrep           -> pip (global)
    - universal-ctags   -> GitHub release zip (per-user, no admin)
    - rust-analyzer     -> GitHub release zip (per-user, no admin)
    - CodeQL bundle     -> GitHub release tar.gz (per-user, no admin)

    Re-run any time to repair a missing tool; existing installs are left
    alone unless a download step fails.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\devtools\setup_devtools.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$ProgramsDir = Join-Path $env:LOCALAPPDATA "Programs"
$TempDir = Join-Path $env:TEMP "enigma-devtools"
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

function Add-ToUserPath {
    param([Parameter(Mandatory)][string]$Directory)
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($userPath -split ';' | Where-Object { $_ })
    if ($parts -notcontains $Directory) {
        $parts += $Directory
        [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
        Write-Host "  [path] Added to user PATH: $Directory"
    }
}

function Test-Command {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-GithubAsset {
    param(
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$NamePattern,
        [Parameter(Mandatory)][string]$OutPath,
        [Parameter(Mandatory)][string]$Kind  # zip | tar.gz
    )
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "ultimate-enigma-devtools" }
    $asset = $release.assets | Where-Object { $_.name -match $NamePattern } | Select-Object -First 1
    if (-not $asset) { throw "No asset matching '$NamePattern' in $Repo $($release.tag_name)" }
    Write-Host "  [get] $($asset.name) from $Repo $($release.tag_name)"
    curl.exe -sL -o $OutPath $asset.browser_download_url
    if (-not (Test-Path $OutPath)) { throw "Download failed: $OutPath" }
    if ($Kind -eq "zip") {
        Expand-Archive -Path $OutPath -DestinationPath (Split-Path $OutPath) -Force
    } else {
        tar -xzf $OutPath -C (Split-Path $OutPath)
    }
    return (Split-Path $OutPath)
}

Write-Host "== CodeGraph dev toolchain setup =="

# ---------------------------------------------------------------- npm bin
$NpmBin = Join-Path $env:APPDATA "npm"
if (Test-Path $NpmBin) { Add-ToUserPath $NpmBin }

# --------------------------------------------------------------- tree-sitter
Write-Host "`n[tool] tree-sitter"
if (-not (Test-Command "tree-sitter")) {
    if (Test-Command "npm") {
        npm install -g --allow-scripts=tree-sitter-cli tree-sitter-cli
    } else { throw "npm not found; install Node.js first." }
} else {
    Write-Host "  [skip] tree-sitter already installed"
}

# ------------------------------------------------------------------- ripgrep
Write-Host "`n[tool] ripgrep"
if (-not (Test-Command "rg")) {
    winget install --id BurntSushi.ripgrep.MSVC --silent --accept-package-agreements --accept-source-agreements --disable-interactivity --scope user
} else {
    Write-Host "  [skip] rg already installed"
}

# -------------------------------------------------------------------- clangd
Write-Host "`n[tool] clangd"
if (-not (Test-Command "clangd")) {
    winget install --id LLVM.clangd --silent --accept-package-agreements --accept-source-agreements --disable-interactivity --scope user
} else {
    Write-Host "  [skip] clangd already installed"
}

# -------------------------------------------------------------------- semgrep
Write-Host "`n[tool] semgrep"
if (-not (Test-Command "semgrep")) {
    if (Test-Command "pip") {
        pip install semgrep
    } else { throw "pip not found; install Python first." }
} else {
    Write-Host "  [skip] semgrep already installed"
}

# ---------------------------------------------------------- universal-ctags
Write-Host "`n[tool] universal-ctags"
if (-not (Test-Command "ctags")) {
    $dir = Join-Path $ProgramsDir "ctags"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $zip = Join-Path $TempDir "ctags-x64.zip"
    Invoke-GithubAsset -Repo "universal-ctags/ctags-win32" -NamePattern "x64\.zip$" -OutPath $zip -Kind "zip"
    Copy-Item -Path (Join-Path (Split-Path $zip) "ctags.exe") -Destination (Join-Path $dir "ctags.exe") -Force
    Add-ToUserPath $dir
} else {
    Write-Host "  [skip] ctags already installed"
}

# -------------------------------------------------------------- rust-analyzer
Write-Host "`n[tool] rust-analyzer"
if (-not (Test-Command "rust-analyzer")) {
    $dir = Join-Path $ProgramsDir "rust-analyzer"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $zip = Join-Path $TempDir "rust-analyzer.zip"
    Invoke-GithubAsset -Repo "rust-lang/rust-analyzer" -NamePattern "x86_64-pc-windows-msvc\.zip$" -OutPath $zip -Kind "zip"
    Copy-Item -Path (Join-Path (Split-Path $zip) "rust-analyzer.exe") -Destination (Join-Path $dir "rust-analyzer.exe") -Force
    Add-ToUserPath $dir
} else {
    Write-Host "  [skip] rust-analyzer already installed"
}

# --------------------------------------------------------------------- codeql
Write-Host "`n[tool] codeql"
if (-not (Test-Command "codeql")) {
    $dir = Join-Path $ProgramsDir "codeql"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $tarball = Join-Path $TempDir "codeql-bundle-win64.tar.gz"
    Invoke-GithubAsset -Repo "github/codeql-action" -NamePattern "codeql-bundle-win64\.tar\.gz$" -OutPath $tarball -Kind "tar.gz"
    if (Test-Path (Join-Path (Split-Path $tarball) "codeql")) {
        Move-Item -Path (Join-Path (Split-Path $tarball) "codeql") -Destination $dir -Force
    }
    Add-ToUserPath $dir
} else {
    Write-Host "  [skip] codeql already installed"
}

Write-Host "`nDone. Open a NEW terminal so PATH changes take effect, then run:"
Write-Host "  codegraph sync   # or just keep coding; CodeGraph auto-syncs"
