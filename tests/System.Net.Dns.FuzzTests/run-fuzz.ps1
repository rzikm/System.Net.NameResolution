<#
.SYNOPSIS
    Builds, instruments, and runs SharpFuzz-based fuzz tests for System.Net.Dns.

.DESCRIPTION
    This script:
    1. Publishes the fuzz test project in Release configuration.
    2. Instruments the System.Net.Dns.dll assembly using the sharpfuzz CLI tool.
    3. Generates seed corpus files (if the corpus directory doesn't exist).
    4. Runs the specified fuzz target using libfuzzer-dotnet-windows.exe.

.PARAMETER Target
    The fuzz target to run. One of: reader, name, writer, roundtrip, name-roundtrip.
    Defaults to "reader".

.PARAMETER LibFuzzerPath
    Path to libfuzzer-dotnet-windows.exe.
    Defaults to "libfuzzer-dotnet-windows.exe" (assumes it's on PATH).

.PARAMETER MaxLen
    Maximum input length for the fuzzer. Defaults to 1024.

.PARAMETER Timeout
    Per-input timeout in seconds. Defaults to 5.

.PARAMETER ExtraArgs
    Additional arguments to pass to libfuzzer-dotnet-windows.exe.

.EXAMPLE
    .\run-fuzz.ps1 -Target reader
    .\run-fuzz.ps1 -Target name -MaxLen 512 -Timeout 10
    .\run-fuzz.ps1 -Target writer -ExtraArgs "-jobs=4","-workers=4"
#>
param(
    [ValidateSet("reader", "name", "writer", "roundtrip", "name-roundtrip")]
    [string]$Target = "reader",

    [string]$LibFuzzerPath = "libfuzzer-dotnet-windows.exe",

    [int]$MaxLen = 1024,

    [int]$Timeout = 5,

    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = "Stop"

$fuzzProjectDir = $PSScriptRoot
$publishDir = Join-Path $fuzzProjectDir "bin\fuzz"
$corpusDir = Join-Path $fuzzProjectDir "corpus\$Target"
$crashDir = Join-Path $fuzzProjectDir "crashes\$Target"
$targetDll = Join-Path $publishDir "System.Net.Dns.dll"
$harnessExe = Join-Path $publishDir "System.Net.Dns.FuzzTests.exe"

# Step 1: Publish the fuzz test project
Write-Host "==> Publishing fuzz test project (Release)..." -ForegroundColor Cyan
dotnet publish $fuzzProjectDir -c Release -o $publishDir --nologo -v quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to publish fuzz test project."
    exit 1
}
Write-Host "    Published to: $publishDir" -ForegroundColor Green

# Step 2: Generate seed corpus if needed (must run BEFORE instrumentation)
if (-not (Test-Path $corpusDir)) {
    Write-Host "==> Generating seed corpus..." -ForegroundColor Cyan
    & $harnessExe generate-seeds
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to generate seed corpus."
        exit 1
    }
    Write-Host "    Seeds generated in: $corpusDir" -ForegroundColor Green
}
else {
    Write-Host "==> Seed corpus already exists at: $corpusDir" -ForegroundColor Yellow
}

# Step 3: Instrument the target assembly
Write-Host "==> Instrumenting System.Net.Dns.dll..." -ForegroundColor Cyan
$output = sharpfuzz $targetDll
if ($LASTEXITCODE -ne 0 -and $output -notmatch "already instrumented") {
    Write-Error "Failed to instrument System.Net.Dns.dll. Ensure 'sharpfuzz' CLI tool is installed: dotnet tool install --global SharpFuzz.CommandLine"
    exit 1
}
Write-Host "    Instrumented successfully." -ForegroundColor Green

# Step 4: Create crash directory
if (-not (Test-Path $crashDir)) {
    New-Item -ItemType Directory -Path $crashDir -Force | Out-Null
}

# Step 5: Run the fuzzer
Write-Host "==> Running fuzzer: $Target" -ForegroundColor Cyan
Write-Host "    Harness:  $harnessExe" -ForegroundColor Gray
Write-Host "    Corpus:   $corpusDir" -ForegroundColor Gray
Write-Host "    Crashes:  $crashDir" -ForegroundColor Gray
Write-Host "    MaxLen:   $MaxLen" -ForegroundColor Gray
Write-Host "    Timeout:  $Timeout" -ForegroundColor Gray
Write-Host ""

$fuzzerArgs = @(
    "--target_path=$harnessExe"
    "--target_arg=$Target"
    $corpusDir
    "-artifact_prefix=$crashDir\"
    "-max_len=$MaxLen"
    "-timeout=$Timeout"
) + $ExtraArgs

& $LibFuzzerPath @fuzzerArgs
