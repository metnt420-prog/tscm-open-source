# 📦 TSCM Installation Guide

Step-by-step instructions for Windows, Linux, and macOS.

---

## Prerequisites

- Python 3.10+ (3.11 recommended)
- Git
- Administrator/root access (required for SDR hardware)

---

## Windows 11 Installation

### Step 1: Install Python

Download Python 3.11 from [python.org](https://python.org/downloads/).
**Check "Add Python to PATH" during installation.**

```powershell
python --version
# Python 3.11.x
```

### Step 2: Install SDR Drivers with Zadig

**For RTL-SDR:**
1. Download [Zadig](https://zadig.akeo.ie/)
2. Plug in your RTL-SDR dongle
3. Run Zadig as Administrator
4. Select the RTL-SDR device (may show as "Bulk-In, Interface")
5. Select "WinUSB" driver and click "Replace Driver"

**For HackRF One:**
1. Download the [HackRF Windows installer](https://github.com/greatscottgadgets/hackrf/releases)
2. Run the installer
3. Verify: `hackrf_info` in Command Prompt (as Admin)

**For BladeRF xA9:**
1. Download [BladeRF Windows installer](https://nuand.com/windows_installers/bladeRF-win-installer-latest.exe)
2. Run as Administrator
3. Verify: `bladeRF-cli -i` and `bladeRF-cli -e "info"`

### Step 3: Install Radioconda (recommended for SDR toolchain)

Download [Radioconda](https://github.com/ryanvolz/radioconda/releases) — provides GNU Radio and all SDR drivers in a conda environment.

```powershell
# After installing, add to PATH:
$env:PATH = "C:\ProgramData\radioconda\Library\bin;" + $env:PATH
```

### Step 4: Clone and Install

```powershell
git clone https://github.com/YOUR_USERNAME/tscm-open-source.git
cd tscm-open-source\tscm_suite

# Create virtual environment (recommended)
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install PyTorch (for NeuralDetector GPU acceleration)
pip install torch --index-url https://download.pytorch.org/whl/cu118

# Install optional dependencies
pip install whisper openai-whisper  # voice transcription
pip install pyubx2 pynmea2          # GPS
pip install pyserial                # serial devices
pip install wmi                     # Windows hardware monitoring
pip install sounddevice             # audio capture
```

### Step 5: Configure

Edit `config.yaml` to match your hardware:

```yaml
# Your home position (required for map)
home_lat: 41.51325
home_lon: -88.13368

# Hardware you own
bladerf_enabled: false    # Set true if you have BladeRF
hackrf_enabled: false     # Set true if you have HackRF
rtlsdr_enabled: true      # Set true if you have RTL-SDR
```

### Step 6: Run

**IMPORTANT: Run as Administrator** (required for SDR hardware access)

```powershell
# Right-click PowerShell → Run as Administrator
cd C:\path\to\tscm-open-source\tscm_suite
.\venv\Scripts\activate
python tscm_main.py
```

Open http://localhost:8080 in your browser.

---

## Linux Installation (Ubuntu/Debian)

### Step 1: Install System Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git \
    libusb-1.0-0-dev libboost-all-dev libfftw3-dev \
    portaudio19-dev libasound2-dev

# SDR tools
sudo apt install -y hackrf rtl-sdr bladerf gnuradio

# Blacklist DVB-T driver (conflicts with RTL-SDR)
echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/blacklist-rtl.conf
```

### Step 2: Install udev Rules (so you don't need sudo)

```bash
# RTL-SDR
sudo wget -O /etc/udev/rules.d/20-rtlsdr.rules \
    https://raw.githubusercontent.com/osmocom/rtl-sdr/master/rtl-sdr.rules

# HackRF
sudo cp /usr/share/hackrf/53-hackrf.rules /etc/udev/rules.d/

# BladeRF
sudo wget -O /etc/udev/rules.d/88-nuand-bladerf1.rules \
    https://raw.githubusercontent.com/Nuand/bladeRF/master/host/utilities/bladeRF/88-nuand-bladerf1.rules
sudo wget -O /etc/udev/rules.d/88-nuand-bladerf2.rules \
    https://raw.githubusercontent.com/Nuand/bladeRF/master/host/utilities/bladeRF/88-nuand-bladerf2.rules

# Reload rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Add your user to plugdev
sudo usermod -a -G plugdev $USER
# Log out and back in
```

### Step 3: Clone and Install

```bash
git clone https://github.com/YOUR_USERNAME/tscm-open-source.git
cd tscm-open-source/tscm_suite

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install torch --index-url https://download.pytorch.org/whl/cpu  # or cu118 for CUDA
pip install whisper openai-whisper pyubx2 pynmea2 pyserial sounddevice
```

### Step 4: Configure and Run

```bash
# Edit config.yaml
nano config.yaml

# Run (no sudo needed if udev rules installed)
python tscm_main.py
```

---

## macOS Installation

### Step 1: Install Homebrew and Python

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install python@3.11 git libusb fftw portaudio

# SDR tools
brew install hackrf rtl-sdr

# BladeRF on macOS is more complex — use the official installer from nuand.com
```

### Step 2: Clone and Install

```bash
git clone https://github.com/YOUR_USERNAME/tscm-open-source.git
cd tscm-open-source/tscm_suite

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install torch  # CPU version
pip install whisper openai-whisper sounddevice
```

### Step 3: Run

```bash
python tscm_main.py
```

---

## Verifying Your Installation

After starting, check the console output for:

```
🛡️ TSCM Source Localization Suite active
============================================
 TSCM MASTER SUITE v2 - SOURCE LOCALIZATION
============================================
 Map: http://localhost:8080
============================================
```

If hardware is detected, you'll see messages like:
- `[HACKRF] HackRF One found` — HackRF connected
- `[BLADERF] bladeRF-cli available` — BladeRF connected  
- `[RTL-SDR] capturing at 850.0 MHz` — RTL-SDR connected
- `[PET] Petterson M500 initialized` — Ultrasonic mic connected
- `[LAPTOP MIC] Initialized 4ch array` — Laptop mic ready

If something isn't found, the system will warn you but continue running with available hardware.

---

## Common Issues

### "Access denied" on Windows
→ Run PowerShell/Terminal **as Administrator**

### "No SDR device found" on Linux
→ Check udev rules are installed and you've logged out/in
→ Try `sudo` once to test, then fix udev

### "USB device not found" / device keeps disconnecting
→ Use a **powered USB 3.0 hub** — BladeRF and HackRF draw significant power
→ Some laptops can't supply enough power through their built-in USB ports

### "No module named 'numpy'"
→ You forgot to activate the virtual environment: `venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Linux/Mac)

### HackRF says "hackrf_transfer not found"
→ Radioconda or HackRF tools not in PATH
→ Windows: `C:\ProgramData\radioconda\Library\bin` must be in PATH
→ Linux: `sudo apt install hackrf`

### BladeRF says "No devices available"
→ Check USB cable is USB 3.0 (blue connector) — BladeRF xA9 requires USB 3.0
→ Run `bladeRF-cli -p` to probe for device

---

## Running on a Raspberry Pi

TSCM can run on a Raspberry Pi 4 (4GB+ RAM recommended). This is great for 24/7 monitoring with low power consumption.

```bash
# Raspberry Pi OS (64-bit)
sudo apt install -y python3-pip gnuradio hackrf rtl-sdr

# Install udev rules as above

# Clone and install
git clone https://github.com/YOUR_USERNAME/tscm-open-source.git
cd tscm-open-source/tscm_suite
pip3 install -r requirements.txt
pip3 install numpy scipy

# Run (headless)
python3 tscm_main.py &
# Open map on another computer: http://<raspberry-pi-ip>:8080
```

**Note:** Raspberry Pi 4 can handle RTL-SDR + HackRF + WiFi scanning. BladeRF xA9 requires USB 3.0 which the Pi 4 has, but CPU may struggle with full 61.44 MHz BW processing. Reduce `BLADERF_SAMPLE_RATE` to 5e6 for Pi.
