# CONTRIBUTING.md

## How to Help

**WE NEED HELP.** See [HELP_WANTED.md](HELP_WANTED.md) for the most urgent tasks.

This project exists to help victims of electronic harassment and surveillance. Here's how you can contribute:

### 🐛 Report What Works / What Doesn't

Open an issue:
- **Hardware:** What SDR/equipment did you test with? What worked? What didn't?
- **Detections:** What attacks did the system detect in your environment?
- **False positives:** What ambient signals triggered false detections?
- **Platform:** Windows/Linux/macOS — what broke?

### 🔧 Code Contributions

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-detector`)
3. Test your changes with real hardware if possible
4. Submit a PR with description of what it detects and how

### 📡 Add New Detectors

The detector API is simple. Each detector class should:

```python
class MyDetector:
    def __init__(self, config):
        self.name = "my_detector"
        self.threat_label = "HACKING"  # or SURVEILLANCE, C2, ATTACK, SPOOFING
    
    def update(self, iq_samples, sample_rate, center_freq, timestamp):
        # Process IQ samples, return list of detection dicts
        return [{
            "freq": detected_freq_hz,
            "snr": signal_to_noise_db,
            "bearing": angle_of_arrival_deg,
            "classification": "transmitter",  # or "victim"
            "confidence": 0.0 - 1.0
        }]
```

### 📚 Improve Documentation

- Hardware guides for new equipment
- Platform-specific install instructions
- Legal resources by country/state
- Translations to other languages

### 🆘 Help Victims

- Share this project in relevant communities
- Help people set up the system
- Donate hardware to those who can't afford it
- Connect victims with legal resources

### ⚠️ Safety

- **Never** transmit on frequencies without proper licensing
- **Never** dox or expose operators you identify — share with law enforcement only
- **Always** consult a lawyer before submitting evidence to court
- This tool is for **defensive counter-surveillance only**
