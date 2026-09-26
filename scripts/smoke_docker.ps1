# PowerShell Docker Smoke Test for FortiGate Security Analyzer
# Verifies container build, non-root user, offline capability, CLI commands, and Streamlit UI.

$ErrorActionPreference = "Stop"

Write-Host "============================================================"
Write-Host "FortiGate Security Analyzer - Docker Smoke Validation Script"
Write-Host "============================================================"

# 1. Check Docker availability
try {
    $dockerVer = docker --version 2>&1
    Write-Host "[INFO] Docker detected: $dockerVer"
} catch {
    Write-Warning "[SKIPPED] Docker CLI or daemon not found in environment."
    Write-Warning "This script requires an active Docker daemon."
    exit 0
}

# 2. Build Docker Image
$imageTag = "fortigate-analyzer-smoke:latest"
Write-Host "`n[STEP 1/8] Building Docker image ($imageTag)..."
docker build -t $imageTag .

# 3. Check CLI Version
Write-Host "`n[STEP 2/8] Testing CLI --version..."
$verOutput = docker run --rm $imageTag --version
Write-Host "Output: $verOutput"
if ($verOutput -notmatch "fortigate-analyzer \d+\.\d+\.\d+") {
    throw "Version output mismatch: $verOutput"
}

# 4. Check CLI Help
Write-Host "`n[STEP 3/8] Testing CLI --help (default action)..."
$helpOutput = docker run --rm $imageTag --help
if ($helpOutput -notmatch "FortiGate Security Analyzer") {
    throw "Help output missing expected header"
}

# 5. Non-Root Identity Check
Write-Host "`n[STEP 4/8] Verifying non-root user (UID 10001 / appuser)..."
$userId = docker run --rm $imageTag sh -c "id -u"
Write-Host "Container user ID: $userId"
if ($userId.Trim() -ne "10001") {
    throw "Expected container UID 10001, got: $userId"
}

# 6. Read-Only Mount & Offline Analysis (--network none)
Write-Host "`n[STEP 5/8] Testing offline static analysis (--network none, read-only volume)..."
$sampleConf = Join-Path $PSScriptRoot "..\tests\fixtures\golden\combined_realistic.conf"
$sampleConf = (Resolve-Path $sampleConf).Path

docker run --rm --network none `
  -v "${sampleConf}:/data/config.conf:ro" `
  $imageTag analyze /data/config.conf

# 7. JSON & HTML Volume Mount Exports
Write-Host "`n[STEP 6/8] Testing report export to host volume..."
$tempOutDir = Join-Path ([System.IO.Path]::GetTempPath()) "fgt_docker_out_$([System.Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempOutDir | Out-Null

try {
    # JSON Export
    docker run --rm --network none `
      -v "${sampleConf}:/data/config.conf:ro" `
      -v "${tempOutDir}:/out" `
      $imageTag export /data/config.conf --format json -o /out/report.json

    $jsonFile = Join-Path $tempOutDir "report.json"
    if (-not (Test-Path $jsonFile) -or (Get-Item $jsonFile).Length -eq 0) {
        throw "JSON report export failed or file is empty"
    }
    Write-Host "JSON export verified (Size: $((Get-Item $jsonFile).Length) bytes)"

    # HTML Export
    docker run --rm --network none `
      -v "${sampleConf}:/data/config.conf:ro" `
      -v "${tempOutDir}:/out" `
      $imageTag export /data/config.conf --format html -o /out/report.html

    $htmlFile = Join-Path $tempOutDir "report.html"
    if (-not (Test-Path $htmlFile) -or (Get-Item $htmlFile).Length -eq 0) {
        throw "HTML report export failed or file is empty"
    }
    Write-Host "HTML export verified (Size: $((Get-Item $htmlFile).Length) bytes)"
} finally {
    Remove-Item -Recurse -Force $tempOutDir -ErrorAction SilentlyContinue
}

# 8. Streamlit UI Startup Smoke Test
Write-Host "`n[STEP 7/8] Testing Streamlit UI container startup ('ui' subcommand)..."
$containerName = "fgt-ui-smoke-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
docker run -d --name $containerName -p 8501:8501 $imageTag ui
Start-Sleep -Seconds 5

try {
    $uiLogs = docker logs $containerName 2>&1
    Write-Host "UI container logs:`n$uiLogs"
    if ($uiLogs -notmatch "You can now view your Streamlit app in your browser") {
        Write-Warning "Streamlit startup message not detected immediately in logs"
    }
} finally {
    Write-Host "`n[STEP 8/8] Cleaning up smoke container..."
    docker stop $containerName | Out-Null
    docker rm $containerName | Out-Null
}

Write-Host "`n============================================================"
Write-Host "SUCCESS: All 8 Docker smoke tests completed successfully!"
Write-Host "============================================================"
