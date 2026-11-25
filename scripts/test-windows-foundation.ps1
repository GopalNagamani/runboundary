# Run from Windows PowerShell. This tests path validation, NOT sandbox isolation.
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this diagnostic on Windows.'
}
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceFile = Join-Path $repoRoot 'internal\platform\windows_paths.rs'
$resultsDir = Join-Path $repoRoot 'test-results'
New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null
$reportFile = Join-Path $resultsDir ('windows-foundation-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '.log')
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('runboundary-foundation-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$testBinary = Join-Path $tempRoot 'windows-path-tests.exe'

function Write-Report([string]$Text) {
    Write-Host $Text
    Add-Content -LiteralPath $reportFile -Value $Text -Encoding UTF8
}

function Invoke-Check([string]$Program, [string[]]$Arguments) {
    # Windows PowerShell can wrap native stderr as ErrorRecords. Capture those
    # without treating normal rustc diagnostics as PowerShell terminating errors.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Program @Arguments 2>&1 | ForEach-Object { Write-Report ([string]$_) }
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
}

try {
    Write-Report 'RunBoundary Windows foundation checks'
    Write-Report ('Report: ' + $reportFile)
    Write-Report ('Windows: ' + [Environment]::OSVersion.VersionString)
    Write-Report 'Scope: lexical Windows path validation only; no agent or AppContainer is launched.'
    Write-Report 'The main RunBoundary CLI still requires a Windows filesystem/process backend.'
    $rustCompiler = (Get-Command rustc -CommandType Application -ErrorAction Stop).Source
    if ((Invoke-Check -Program $rustCompiler -Arguments @('--version')) -ne 0) { throw 'rustc version check failed' }
    Write-Report 'Compiling the standalone foundation tests...'
    if ((Invoke-Check -Program $rustCompiler -Arguments @('--edition=2021', '--test', $sourceFile, '-o', $testBinary)) -ne 0) {
        throw 'Windows foundation test compilation failed'
    }
    Write-Report 'Running foundation tests on Windows...'
    if ((Invoke-Check -Program $testBinary -Arguments @('--nocapture', '--test-threads=1')) -ne 0) {
        throw 'Windows foundation tests failed'
    }
    Write-Report 'Foundation checks passed. Windows sandbox security remains UNVERIFIED.'
} catch {
    Write-Report ('FAILED: ' + $_.Exception.Message)
    exit 1
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
