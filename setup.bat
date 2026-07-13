@echo off
REM ============================================================
REM TSCM Suite - Quick Setup Script
REM ============================================================
REM This script sets up the TSCM suite on Windows.
REM Run as Administrator for SDR driver installation.
REM ============================================================

echo.
echo ==========================================
echo   TSCM Suite - Quick Setup
echo   Technical Surveillance Counter-Measures
echo ==========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.9+ is required but not found.
    echo Please install from: https://python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python found: 
python --version

REM Create virtual environment
echo.
echo [1/4] Setting up Python virtual environment...
if not exist venv (
    python -m venv venv
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment already exists.
)

REM Activate and install dependencies
echo.
echo [2/4] Installing dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip -q
pip install -r tscm_suite\requirements.txt
echo [OK] Dependencies installed.

REM Create required directories
echo.
echo [3/4] Creating data directories...
if not exist models mkdir models
if not exist evidence_hourly mkdir evidence_hourly
if not exist decoded_voice\wav mkdir decoded_voice\wav
echo [OK] Directories ready.

REM Copy example config
echo.
echo [4/4] Setting up configuration...
if not exist tscm_suite\config.yaml (
    copy tscm_suite\config.yaml.example tscm_suite\config.yaml >nul 2>&1
    echo [NOTE] Created config.yaml from example. EDIT IT with your location and hardware!
) else (
    echo [OK] config.yaml already exists.
)

echo.
echo ==========================================
echo   Setup Complete!
echo ==========================================
echo.
echo NEXT STEPS:
echo 1. Edit tscm_suite\config.yaml with your location and hardware
echo 2. Install SDR drivers:
echo    - RTL-SDR: Run Zadig, select device, install WinUSB driver
echo    - HackRF: https://github.com/greatscottgadgets/hackrf/releases
echo    - BladeRF: Run bladeRF-win-installer.exe from nuand.com
echo 3. Run the system:
echo    python tscm_suite\tscm_main.py
echo.
echo The map will be at: http://localhost:8080/
echo.
pause
