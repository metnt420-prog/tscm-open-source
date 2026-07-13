#!/bin/bash
# TSCM Suite - Quick Setup Script (Linux/macOS)
set -e

echo "=========================================="
echo "  TSCM Suite - Quick Setup"
echo "  Technical Surveillance Counter-Measures"
echo "=========================================="
echo

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3.9+ is required but not found."
    exit 1
fi
echo "[OK] Python found: $(python3 --version)"

# Create virtual environment
echo "[1/4] Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "[OK] Virtual environment created."
else
    echo "[OK] Virtual environment already exists."
fi

# Activate and install
echo "[2/4] Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r tscm_suite/requirements.txt
echo "[OK] Dependencies installed."

# Create directories
echo "[3/4] Creating data directories..."
mkdir -p models evidence_hourly decoded_voice/wav
echo "[OK] Directories ready."

# Config
echo "[4/4] Setting up configuration..."
if [ ! -f "tscm_suite/config.yaml" ]; then
    echo "[NOTE] Create tscm_suite/config.yaml from the example and edit it!"
fi

echo
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo
echo "NEXT STEPS:"
echo "1. Edit tscm_suite/config.yaml with your location and hardware"
echo "2. Install SDR drivers for your hardware"
echo "3. Run: python3 tscm_suite/tscm_main.py"
echo "4. Map at: http://localhost:8080/"
echo
