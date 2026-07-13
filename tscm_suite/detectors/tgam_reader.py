"""TGAM EEG Reader module - importable by tscm_final.py for second TGAM (COM7).

ThinkGear AM protocol parser. COM6=HR-SOC336, COM7=HR-SOC284.
Packets: 0xAA 0xAA 0x20 <payload 32B> <checksum>
Provides signal_quality, attention, meditation, delta/theta/alpha/beta/gamma.
"""
import serial
from collections import deque


class TGAMReader:
    """Read ThinkGear AM (TGAM) EEG modules via serial."""
    def __init__(self, port, baud=57600):
        self.port = port; self.baud = baud; self.ser = None
        self.buffer = deque(maxlen=250*3)
        self.last_read_ts = 0
        self.last_values = {
            'signal': 200, 'attention': 0, 'meditation': 0,
            'delta': 0, 'theta': 0, 'alpha_low': 0, 'alpha_high': 0,
            'beta_low': 0, 'beta_high': 0, 'gamma_low': 0, 'gamma_mid': 0
        }
        self._connect()

    def _connect(self):
        try:
            if hasattr(self, 'ser') and self.ser:
                try: self.ser.close()
                except: pass
                self.ser = None
            self.ser = serial.Serial(self.port, self.baud, timeout=0.1)
            self.ser.reset_input_buffer()
            print(f"TGAM EEG on {self.port} at {self.baud} baud")
            return True
        except Exception as e:
            print(f"TGAM {self.port} failed: {e}")
            self.ser = None
            return False

    def _parse_packet(self, payload):
        """Parse ThinkGear payload bytes into dict of values."""
        vals = self.last_values.copy()
        i = 0
        while i < len(payload) - 1:
            code = payload[i]
            if code == 0x80:
                i += 3
            elif code == 0x02:
                vals['signal'] = payload[i+1] if i+1 < len(payload) else 200
                i += 2
            elif code == 0x04:
                vals['attention'] = payload[i+1] if i+1 < len(payload) else 0
                i += 2
            elif code == 0x05:
                vals['meditation'] = payload[i+1] if i+1 < len(payload) else 0
                i += 2
            elif code == 0x83:
                if i+25 <= len(payload):
                    vals['delta'] = (payload[i+1]<<16|payload[i+2]<<8|payload[i+3])/1000.
                    vals['theta'] = (payload[i+4]<<16|payload[i+5]<<8|payload[i+6])/1000.
                    vals['alpha_low'] = (payload[i+7]<<16|payload[i+8]<<8|payload[i+9])/1000.
                    vals['alpha_high'] = (payload[i+10]<<16|payload[i+11]<<8|payload[i+12])/1000.
                    vals['beta_low'] = (payload[i+13]<<16|payload[i+14]<<8|payload[i+15])/1000.
                    vals['beta_high'] = (payload[i+16]<<16|payload[i+17]<<8|payload[i+18])/1000.
                    vals['gamma_low'] = (payload[i+19]<<16|payload[i+20]<<8|payload[i+21])/1000.
                    vals['gamma_mid'] = (payload[i+22]<<16|payload[i+23]<<8|payload[i+24])/1000.
                i += 25
            elif code >= 0x80:
                if i+1 < len(payload): i += payload[i+1] + 2
                else: i += 2
            else:
                i += 2
        self.last_values = vals
        return vals

    def read(self):
        """Read one EEG sample. Returns float value."""
        if not self.ser: return 0.0
        try:
            while self.ser.in_waiting >= 2:
                b = self.ser.read(1)[0]
                if b == 0xAA:
                    b2 = self.ser.read(1)
                    if not b2: return 0.0
                    if b2[0] == 0xAA:
                        plen_b = self.ser.read(1)
                        if not plen_b: return 0.0
                        plen = plen_b[0]
                        if 0 < plen < 170:
                            payload = self.ser.read(plen)
                            if len(payload) == plen:
                                self.ser.read(1)  # checksum
                                vals = self._parse_packet(payload)
                                val = vals.get('beta_high', 0) * 0.001
                                val += vals.get('gamma_mid', 0) * 0.001
                                self.buffer.append(val)
                                return val
                    elif b2[0] >= 0x80:
                        code = b2[0]
                        if code == 0x80 and self.ser.in_waiting >= 2:
                            hi = self.ser.read(1)[0]
                            lo = self.ser.read(1)[0]
                            raw = ((hi << 8) | lo)
                            if raw > 32767: raw -= 65536
                            val = raw * 0.000001
                            self.buffer.append(val)
                            return val
                        elif code == 0x83 and self.ser.in_waiting >= 24:
                            bands = list(self.ser.read(24))
                            self.last_values['delta'] = (bands[0]<<16|bands[1]<<8|bands[2])/1000.
                            self.last_values['theta'] = (bands[3]<<16|bands[4]<<8|bands[5])/1000.
                            self.last_values['alpha_low'] = (bands[6]<<16|bands[7]<<8|bands[8])/1000.
                            self.last_values['alpha_high'] = (bands[9]<<16|bands[10]<<8|bands[11])/1000.
                            self.last_values['beta_low'] = (bands[12]<<16|bands[13]<<8|bands[14])/1000.
                            self.last_values['beta_high'] = (bands[15]<<16|bands[16]<<8|bands[17])/1000.
                            self.last_values['gamma_low'] = (bands[18]<<16|bands[19]<<8|bands[20])/1000.
                            self.last_values['gamma_mid'] = (bands[21]<<16|bands[22]<<8|bands[23])/1000.
                            val = self.last_values['beta_high'] * 0.001 + self.last_values['gamma_mid'] * 0.001
                            self.buffer.append(val)
                            return val
                        else:
                            if self.ser.in_waiting >= 1:
                                v = self.ser.read(1)[0]
                                if code == 0x04: self.last_values['attention'] = v
                                elif code == 0x05: self.last_values['meditation'] = v
                                elif code == 0x02: self.last_values['signal'] = v
            return 0.0
        except:
            return 0.0

    def drain(self):
        """Drain available samples from serial buffer. Capped to prevent infinite loop."""
        count = 0
        if not self.ser: return 0
        try:
            for _ in range(500):  # cap: don't block forever on live stream
                if self.ser.in_waiting <= 0:
                    break
                v = self.read()
                if v != 0.0: count += 1
                else: break
        except: pass
        return count
