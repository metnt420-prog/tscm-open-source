"""Configure ZED-F9P GPS dongles to output NMEA on both COM ports."""
import serial, time, struct

def enable_nmea(port, baud=38400):
    """Send UBX CFG-MSG commands to enable NMEA output."""
    try:
        s = serial.Serial(port, baud, timeout=2)
        print(f"Connected to {port} at {baud}")

        # UBX-CFG-MSG: Enable NMEA messages
        # Class=0x06, ID=0x01, payload=[msgClass, msgID, rate1, rate2, ...]
        # msgClass=0xF0=NMEA, msgID=0x00=GGA, 0x01=GLL, 0x02=GSA, 0x03=GSV, 0x04=RMC, 0x05=VTG

        nmea_msgs = [
            (0xF0, 0x00, 1),  # GGA - every measurement
            (0xF0, 0x01, 1),  # GLL
            (0xF0, 0x02, 1),  # GSA
            (0xF0, 0x03, 1),  # GSV
            (0xF0, 0x04, 1),  # RMC
            (0xF0, 0x05, 1),  # VTG
        ]

        for msg_class, msg_id, rate in nmea_msgs:
            # Build UBX-CFG-MSG payload
            payload = bytes([msg_class, msg_id, rate, rate, rate, rate])
            # Build UBX frame
            length = len(payload)
            frame = bytes([0xB5, 0x62, 0x06, 0x01]) + struct.pack('<H', length) + payload
            # Calculate checksum
            ck_a = ck_b = 0
            for b in frame[2:]:
                ck_a = (ck_a + b) & 0xFF
                ck_b = (ck_b + ck_a) & 0xFF
            frame += bytes([ck_a, ck_b])
            s.write(frame)

        print(f"  Sent NMEA enable commands")

        # Wait and check for NMEA output
        time.sleep(2)
        for i in range(10):
            line = s.readline().decode('ascii', errors='ignore').strip()
            if line.startswith('$'):
                print(f"  NMEA: {line[:80]}")
                break
        else:
            # Try 9600 baud
            s.close()
            s = serial.Serial(port, 9600, timeout=2)
            time.sleep(1)
            for i in range(10):
                line = s.readline().decode('ascii', errors='ignore').strip()
                if line.startswith('$'):
                    print(f"  NMEA at 9600: {line[:80]}")
                    break
            else:
                print(f"  No NMEA output - GPS may need clear sky view")

        # Also try sending UBX-POLL to check if device responds
        s.write(b'\xB5\x62\x0A\x04\x00\x00\x0E\x34')  # UBX-MON-VER poll
        time.sleep(1)
        resp = s.read(200)
        if resp and resp[:2] == b'\xb5\x62':
            print(f"  Device responds to UBX (class={resp[2]:02x} id={resp[3]:02x})")

        s.close()
    except Exception as e:
        print(f"  Error: {e}")

# Configure both GPS dongles
print("=== COM7 ===")
enable_nmea('COM7')
print("\n=== COM6 ===")
enable_nmea('COM6')
