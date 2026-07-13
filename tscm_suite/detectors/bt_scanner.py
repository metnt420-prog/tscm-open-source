#!/usr/bin/env python
import asyncio, json, os, time
from bleak import BleakScanner

WS = r'C:\Users\carpe\.openclaw-autoclaw\workspace'
OUT = os.path.join(WS, 'bt_devices.jsonl')

async def scan():
    print('Bluetooth BLE scan...')
    try:
        devices = await BleakScanner.discover(timeout=5.0)
        for d in devices:
            rssi = getattr(d, 'rssi', 0)
            name = getattr(d, 'name', '?') or '?'
            dist = 'NEAR' if rssi > -50 else 'CLOSE' if rssi > -70 else 'FAR'
            print(f'  {d.address} {dist:6s} RSSI={rssi} {name[:40]}')
        
        with open(OUT, 'a') as f:
            data = {
                'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'devices': [
                    {'addr': d.address, 'rssi': getattr(d,'rssi',0), 
                     'name': getattr(d,'name','?') or '?'}
                    for d in devices
                ]
            }
            json.dump(data, f)
            f.write('\n')
        print(f'Saved {len(devices)} devices to {OUT}')
    except Exception as e:
        print(f'BT scan error: {e}')

asyncio.run(scan())
