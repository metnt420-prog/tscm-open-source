"""
WiFi Repeater Deep Analyzer
Scans for repeaters, bridges, and unauthorized devices on the network.
Correlates WiFi signals with ARP, DNS, and traffic patterns.
"""
import subprocess
import re
import time
import json
import os
from collections import defaultdict

class WiFiRepeaterAnalyzer:
    def __init__(self, log=None):
        self.log = log
        self.scan_history = []
        self.device_profiles = {}  # mac -> profile
        self.suspicious_devices = []
        self.evidence_file = os.path.join(os.path.dirname(__file__), 'models', 'wifi_evidence.json')
        
    def full_scan(self):
        """Run a complete WiFi + network analysis."""
        results = {
            'timestamp': time.time(),
            'wifi_networks': self._scan_wifi(),
            'arp_table': self._scan_arp(),
            'dns_cache': self._scan_dns(),
            'connections': self._scan_connections(),
            'suspicious': []
        }
        
        # Analyze for repeaters and C2
        results['suspicious'] = self._analyze(results)
        
        self.scan_history.append(results)
        if len(self.scan_history) > 50:
            self.scan_history = self.scan_history[-50:]
        
        # Save evidence
        self._save_evidence(results)
        
        return results
    
    def _scan_wifi(self):
        """Scan all visible WiFi networks with BSSID details."""
        networks = []
        try:
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True, timeout=15, encoding='utf-8', errors='replace')
            
            current = {}
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('SSID'):
                    if current.get('ssid') is not None:
                        networks.append(current)
                    ssid = line.split(':', 1)[1].strip() if ':' in line else ''
                    current = {'ssid': ssid, 'bssids': []}
                elif 'BSSID' in line and ':' in line:
                    bssid = line.split(':', 1)[1].strip()
                    current['bssids'].append({'mac': bssid})
                elif 'Signal' in line and ':' in line:
                    sig = line.split(':', 1)[1].strip().rstrip('%')
                    if current['bssids']:
                        current['bssids'][-1]['signal'] = int(sig) if sig.isdigit() else 0
                elif 'Channel' in line and ':' in line:
                    ch = line.split(':', 1)[1].strip()
                    if current['bssids']:
                        current['bssids'][-1]['channel'] = int(ch) if ch.isdigit() else 0
                elif 'Band' in line and ':' in line:
                    band = line.split(':', 1)[1].strip()
                    if current['bssids']:
                        current['bssids'][-1]['band'] = band
                elif 'Authentication' in line and ':' in line:
                    current['auth'] = line.split(':', 1)[1].strip()
                elif 'Encryption' in line and ':' in line:
                    current['encryption'] = line.split(':', 1)[1].strip()
                elif 'Radio type' in line and ':' in line:
                    if current['bssids']:
                        current['bssids'][-1]['radio'] = line.split(':', 1)[1].strip()
                elif 'Connected Stations' in line:
                    match = re.search(r'(\d+)', line)
                    if match and current['bssids']:
                        current['bssids'][-1]['stations'] = int(match.group(1))
            
            if current.get('ssid') is not None:
                networks.append(current)
                
        except Exception as e:
            if self.log: self.log.debug('WiFi scan error: %s' % e)
        
        # Flag spoofed MACs
        for net in networks:
            for b in net['bssids']:
                mac = b.get('mac', '')
                if len(mac) >= 2:
                    first_byte = int(mac.replace(':', '').replace('-', '')[:2], 16)
                    b['mac_spoofed'] = bool(first_byte & 0x02)
        
        return networks
    
    def _scan_arp(self):
        """Scan ARP table for devices on local network."""
        devices = []
        try:
            output = subprocess.check_output(['arp', '-a'], capture_output=True, text=True, timeout=5)
            for line in output.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+(\w+)', line, re.I)
                if match:
                    ip, mac, dtype = match.groups()
                    if mac != 'ff-ff-ff-ff-ff-ff':
                        first_byte = int(mac.replace('-', '')[:2], 16)
                        devices.append({
                            'ip': ip,
                            'mac': mac,
                            'type': dtype,
                            'mac_spoofed': bool(first_byte & 0x02)
                        })
        except Exception as e:
            if self.log: self.log.debug('ARP scan error: %s' % e)
        return devices
    
    def _scan_dns(self):
        """Check DNS cache for C2 domains."""
        domains = []
        try:
            output = subprocess.check_output(
                ['ipconfig', '/displaydns'], capture_output=True, text=True, timeout=10,
                encoding='utf-8', errors='replace')
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('Record Name'):
                    domain = line.split(':', 1)[1].strip()
                    if domain and not domain.endswith('local') and '.' in domain:
                        domains.append(domain)
        except: pass
        return list(set(domains))[:50]
    
    def _scan_connections(self):
        """Check active network connections for C2 traffic."""
        conns = []
        try:
            output = subprocess.check_output(
                ['netstat', '-ano'], capture_output=True, text=True, timeout=10)
            for line in output.split('\n'):
                if 'ESTABLISHED' in line or 'TIME_WAIT' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        conns.append({
                            'proto': parts[0],
                            'local': parts[1],
                            'remote': parts[2],
                            'state': parts[3],
                            'pid': parts[4]
                        })
        except: pass
        return conns
    
    def _analyze(self, results):
        """Analyze scan results for repeaters, C2, and suspicious patterns."""
        suspicious = []
        
        # 1. Find spoofed MAC networks (repeaters with fake identities)
        for net in results['wifi_networks']:
            for b in net.get('bssids', []):
                if b.get('mac_spoofed'):
                    suspicious.append({
                        'type': 'SPOOFED_WIFI_DEVICE',
                        'ssid': net.get('ssid', '<hidden>'),
                        'mac': b.get('mac'),
                        'signal': b.get('signal', 0),
                        'channel': b.get('channel', 0),
                        'radio': b.get('radio', ''),
                        'detail': 'Locally administered MAC = device is hiding real identity',
                        'severity': 'HIGH' if b.get('signal', 0) > 50 else 'MEDIUM'
                    })
        
        # 2. Find repeaters (802.11g only = cheap extender)
        for net in results['wifi_networks']:
            for b in net.get('bssids', []):
                radio = b.get('radio', '')
                if 'g' in radio and 'n' not in radio and 'ac' not in radio and 'ax' not in radio:
                    if net.get('ssid', '') not in ['OpenBCI-3D8A']:  # exclude known devices
                        suspicious.append({
                            'type': 'WIFI_REPEATER',
                            'ssid': net.get('ssid', '<hidden>'),
                            'mac': b.get('mac'),
                            'signal': b.get('signal', 0),
                            'channel': b.get('channel', 0),
                            'detail': '802.11g only = cheap repeater/extender, not a modern device',
                            'severity': 'HIGH'
                        })
        
        # 3. Find unknown devices on local network
        known_ips = {'192.168.1.1', '192.168.1.238', '192.168.1.255'}
        for dev in results['arp_table']:
            if dev['ip'] not in known_ips and dev['type'] == 'dynamic':
                suspicious.append({
                    'type': 'UNKNOWN_NETWORK_DEVICE',
                    'ip': dev['ip'],
                    'mac': dev['mac'],
                    'mac_spoofed': dev.get('mac_spoofed', False),
                    'detail': 'Unknown device on local network - could be repeater bridge',
                    'severity': 'CRITICAL'
                })
        
        # 4. Find hidden SSIDs
        for net in results['wifi_networks']:
            if not net.get('ssid', '').strip():
                suspicious.append({
                    'type': 'HIDDEN_SSID',
                    'mac': [b.get('mac') for b in net.get('bssids', [])],
                    'auth': net.get('auth', ''),
                    'detail': 'Hidden SSID = device trying to avoid detection',
                    'severity': 'MEDIUM'
                })
        
        # 5. Find open networks (attack vector)
        for net in results['wifi_networks']:
            if net.get('auth') == 'Open' and net.get('ssid') != 'OpenBCI-3D8A':
                suspicious.append({
                    'type': 'OPEN_NETWORK',
                    'ssid': net.get('ssid'),
                    'detail': 'Open WiFi = potential injection/honeypot vector',
                    'severity': 'HIGH'
                })
        
        # 6. Correlate: repeater + spoofed MAC + same channel as your router = MITM
        your_channels = set()
        for net in results['wifi_networks']:
            if net.get('ssid') == 'min':  # your router
                for b in net.get('bssids', []):
                    your_channels.add(b.get('channel'))
        
        for net in results['wifi_networks']:
            for b in net.get('bssids', []):
                if b.get('channel') in your_channels and b.get('mac_spoofed') and net.get('ssid') != 'min':
                    suspicious.append({
                        'type': 'SAME_CHANNEL_MITM',
                        'ssid': net.get('ssid'),
                        'mac': b.get('mac'),
                        'channel': b.get('channel'),
                        'detail': 'Spoofed device on SAME channel as your router = potential MITM/repeater',
                        'severity': 'CRITICAL'
                    })
        
        # 7. DNS analysis - look for C2 domains
        c2_patterns = ['discord', 'telegram', 'signal', 'ngrok', 'cloudflare-workers', 
                       'dynamic-dns', 'duckdns', 'noip', 'ddns']
        for domain in results.get('dns_cache', []):
            for pattern in c2_patterns:
                if pattern in domain.lower():
                    suspicious.append({
                        'type': 'C2_DNS',
                        'domain': domain,
                        'pattern': pattern,
                        'detail': 'DNS lookup matching C2 pattern: %s' % pattern,
                        'severity': 'HIGH'
                    })
                    break
        
        return suspicious
    
    def _save_evidence(self, results):
        """Save scan results as evidence."""
        try:
            os.makedirs(os.path.dirname(self.evidence_file), exist_ok=True)
            evidence = []
            if os.path.exists(self.evidence_file):
                with open(self.evidence_file, 'r') as f:
                    evidence = json.load(f)
            evidence.append({
                'timestamp': results['timestamp'],
                'suspicious_count': len(results['suspicious']),
                'suspicious': results['suspicious'][:20],  # top 20
                'wifi_count': len(results['wifi_networks']),
                'arp_count': len(results['arp_table'])
            })
            # Keep last 100 scans
            evidence = evidence[-100:]
            with open(self.evidence_file, 'w') as f:
                json.dump(evidence, f, indent=2)
        except: pass
    
    def get_device_profile(self, mac):
        """Get or create a device profile for tracking."""
        if mac not in self.device_profiles:
            self.device_profiles[mac] = {
                'first_seen': time.time(),
                'last_seen': time.time(),
                'signal_history': [],
                'channel_history': [],
                'ssid_history': [],
                'observation_count': 0,
                'flags': []
            }
        return self.device_profiles[mac]
