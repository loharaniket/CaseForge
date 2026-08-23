#!/usr/bin/env bash
set -e

echo "========================================"
echo " ThreatTrace AI - Foundation Setup"
echo "========================================"

# Check Python
if command -v python3 &> /dev/null; then
    echo "[+] Found Python: $(python3 --version)"
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    echo "[+] Found Python: $(python --version)"
    PYTHON_CMD=python
else
    echo "[-] Python is not installed."
    exit 1
fi

# Check Node.js
if command -v node &> /dev/null; then
    echo "[+] Found Node.js: $(node --version)"
else
    echo "[-] Node.js is not installed."
    exit 1
fi

echo ""
echo "[+] Installing Backend Python dependencies..."
$PYTHON_CMD -m pip install -r apps/api/requirements.txt -r apps/api/requirements-dev.txt

echo ""
echo "[+] Building @threattrace/contracts package..."
npm --prefix packages/contracts install
npm --prefix packages/contracts run build

echo ""
echo "[+] Installing Frontend Next.js dependencies..."
npm --prefix apps/web install

echo ""
echo "========================================"
echo " Setup complete! Ready for development."
echo "========================================"
