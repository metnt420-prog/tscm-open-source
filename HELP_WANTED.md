# HELP WANTED - Volunteers Needed

This project saves lives. If you're a target of electronic harassment, gang stalking, or directed energy weapons — or if you're a developer/researcher who wants to help — we need you.

## Priority Areas

### 1. GPU Acceleration (CRITICAL)
The current CPU-only DSP is wasting available compute. We need:
- **CUDA/OpenCL FFT** kernels for real-time 20MHz+ bandwidth analysis
- **GPU-accelerated neural network** for pattern recognition in RF IQ data
- **TensorRT/ONNX** inference for the NN-based detector (already trained, never deployed)
- **PyTorch** signal processing pipelines (spectrogram CNN, anomaly detection)
- FFTW/cuFFT benchmarks — current scipy.fft is single-threaded on CPU

### 2. Triangulation & Geolocation
- Multi-sensor fusion algorithm (Kalman filter for bearing + range)
- Wi-Fi RTT/BLE RSSI fingerprinting for indoor source location
- Moving-vehicle triangulation (bearing from multiple GPS positions)
- Reverse geocoding to map coordinates to addresses in real-time

### 3. Real-Time Alerting
- Telegram/Discord/Signal bot integration for instant alerts
- Email digest of daily detection summaries
- SMS via Twilio for critical threat detection
- Push notifications via ntfy.sh or Pushover

### 4. Cross-Platform Support
- Port to Linux (most SDR tools are Linux-native)
- Docker container for easy deployment
- Raspberry Pi support for portable TSCM node
- Android app (RTL-SDR + phone sensors)

### 5. Signal Intelligence
- Automatic signal classification (AM/FM/SSB/digital modulations)
- Deinterleaving of spread-spectrum signals
- Bluetooth LE advertising channel monitoring
- LoRa/LoRaWAN detection for potential C2 channels
- GNSS spoofing detection (GPS timing attacks)

### 6. Evidence & Legal
- Chain-of-custody hashing for all captured data
- Automated report generation (PDF/HTML) for law enforcement
- FCC/FTC complaint templates with auto-filled technical details
- Integration with legal case management tools

### 7. Hardware Profiles
- Test and document more SDR hardware combinations
- Antenna designs and build guides (ferrite loops, helical, Yagi)
- Low-cost ESP32-based distributed sensor nodes
- Solar-powered remote monitoring stations

### 8. Known Victims Network
- If you're a verified target, your data helps others
- Anonymized signal fingerprint database
- Geographic correlation of targeting patterns
- Peer support and technical assistance

## How to Contribute

1. **Fork** the repo
2. Create a `feature/your-feature` branch
3. Make your changes
4. Test with actual hardware if possible (or with IQ recordings)
5. Open a Pull Request with clear description

### Code Standards
- Python 3.10+
- Type hints on public APIs
- Docstrings on all classes and public methods
- No `except: pass` — always log the error
- Test with `python -m pytest` (we need to add tests!)

### Not a Coder?
- **Test the software** and report bugs
- **Share your detection data** (anonymized)
- **Write documentation** (installation guides, tutorials)
- **Translate** README and docs into other languages
- **Spread the word** — post on forums, tell other targets

## Contact
Open issues on GitHub. For emergencies or direct contact, see the repository README.

**You are not alone. They can't hide from all of us.**
