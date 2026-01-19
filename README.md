# ble_airtag_sniff

A small Python tool to scan **BLE advertisements** and detect **Apple manufacturer-specific** frames that look like **AirTag / Find My** beacons.

It focuses on BLE **Manufacturer Specific Data** (AD type `0xFF`) and applies a simple heuristic:

- Company ID == **Apple (0x004C)**
- Apple payload starts with:
  - `apple_type == 0x12`
  - `apple_len >= 0x19` (classic `0x19` or larger)
- Optionally require reconstructed AD-structure length byte `== 0x1E`

For matching frames, it chunks the Apple payload (`12 19 ...`) into:

- `hdr2` (2 bytes)
- `blk16` (16 bytes) — best short-term “core correlation” block
- `tail` (remainder) — often changes while `blk16` stays stable (state/counter-ish)

> **Note (macOS):** you may see UUID-like “addresses” instead of `AA:BB:CC:DD:EE:FF` due to BLE privacy behavior.

---

## Requirements

- Python3
- BLE adapter supported by your OS
- **Permissions**
  - **macOS**: grant Bluetooth permissions to Terminal / iTerm (or the app running Python). 
  You can remove "Terminal" in app permissions after running it. 
  - **Linux**: you may need elevated permissions depending on distro/BLE stack

---

## Install and Run Prep

### macOS / Linux
```bash
git clone https://github.com/nitekry/airtag-recon
cd airtag-recon

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install bleak
```

---
## Initial recon with Airtag present

### 1 hour scan to watch for rotation of OUI
```bash
python3 airtag_sniff.py --duration 3600 --print-on-change --change-field any --dedup 0
```

### quick proximity check
```bash
python3 airtag_sniff.py --duration 120 --print-on-change --change-field blk16 --dedup 0
```

### 15 minute scan to check for payload tail changes
```bash
python3 airtag_sniff.py --duration 900 --print-on-change --change-field tail --dedup 0
```

---

## Results

### You should see several lines 5 to 10 with one airtag present.

```bash
[AIRTAG?] CHANGED(FIRST) C04FE99D-584A-9DA3-6596-8B421DD73B8F RSSI: -94 type:0x12 len:0x19 adlen:0x1E hdr2:90D3 blk16:E115A1619B1005A717510F3A95ADB90F tail:1CED9BFFE402F1 fp_full:a1b011a88a5e fp_blk16:3205ee559185 fp_tail:a15b86b1090d mfg:121990D3E115A1619B1005A717510F3A95ADB90F1CED9BFFE402F1
[AIRTAG?] CHANGED(TAIL) C04FE99D-584A-9DA3-6596-8B421DD73B8F RSSI: -97 type:0x12 len:0x19 adlen:0x1E hdr2:90D3 blk16:E115A1619B1005A717510F3A95ADB90F tail:1CED9BFFE402BE fp_full:8a1aab4c2f09 fp_blk16:3205ee559185 fp_tail:5d698133aaaf mfg:121990D3E115A1619B1005A717510F3A95ADB90F1CED9BFFE402BE
[AIRTAG?] CHANGED(FIRST) 57219766-A8ED-F8A3-D2B9-5AD01D7AB914 RSSI: -99 type:0x12 len:0x19 adlen:0x1E hdr2:6A7A blk16:47E432C40E896A0795AED68B4F3C8C09 tail:2DD26D067E005D fp_full:c8683105324a fp_blk16:2e18e6fe03f9 fp_tail:ca7396663a87 mfg:12196A7A47E432C40E896A0795AED68B4F3C8C092DD26D067E005D
[AIRTAG?] CHANGED(FIRST) 9AE0D755-D31D-88D4-082A-5F36962F877E RSSI: -93 type:0x12 len:0x19 adlen:0x1E hdr2:6A2D blk16:C4CB9EA58EAAB091D84FE3DDABE60FA5 tail:0351F4D4DD00D1 fp_full:1a919aac3949 fp_blk16:db024a99a31d fp_tail:38a0908ca643 mfg:12196A2DC4CB9EA58EAAB091D84FE3DDABE60FA50351F4D4DD00D1
[AIRTAG?] CHANGED(FIRST) D1E8A9FB-8EAE-E4E7-29AC-C6CE26C26AEA RSSI: -95 type:0x12 len:0x19 adlen:0x1E hdr2:003F blk16:D212AF963B19FA956389B769705A339E tail:3A5B88561B0300 fp_full:bae1f3614ff4 fp_blk16:71331ec7b4a5 fp_tail:84b1ea3d18fb mfg:1219003FD212AF963B19FA956389B769705A339E3A5B88561B0300
```
## Copy and paste these to a text file or something like pastebin and send to me in Discord. OrdoOuroborus
