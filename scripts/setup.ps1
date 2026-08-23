# ThreatTrace AI — Local Development Setup Script (PowerShell)
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ThreatTrace AI - Foundation Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check Python
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pyVer = python --version
    Write-Host "[+] Found Python: $pyVer" -ForegroundColor Green
} else {
    Write-Host "[-] Python is not installed or not in PATH." -ForegroundColor Red
}

# Check Node.js
if (Get-Command node -ErrorAction SilentlyContinue) {
    $nodeVer = node --version
    Write-Host "[+] Found Node.js: $nodeVer" -ForegroundColor Green
} else {
    Write-Host "[-] Node.js is not installed or not in PATH." -ForegroundColor Red
}

# Install Python backend dependencies
Write-Host "`n[+] Installing Backend Python dependencies..." -ForegroundColor Yellow
python -m pip install -r apps/api/requirements.txt -r apps/api/requirements-dev.txt

# Install Shared Contracts dependencies
Write-Host "`n[+] Building @threattrace/contracts package..." -ForegroundColor Yellow
npm --prefix packages/contracts install
npm --prefix packages/contracts run build

# Install Frontend dependencies
Write-Host "`n[+] Installing Frontend Next.js dependencies..." -ForegroundColor Yellow
npm --prefix apps/web install

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " Setup complete! Ready for development." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
