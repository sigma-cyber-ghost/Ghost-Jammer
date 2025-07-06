# Ghost-Jammer - Professional WiFi Security Toolkit

Ghost-Jammer is a powerful WiFi security toolkit designed for authorized penetration testing and security research. It provides a comprehensive suite of tools for network scanning, deauthentication attacks, and handshake capture in an intuitive command-line interface.

Key Features
Network Scanning: Discover nearby WiFi networks with detailed information

Target Selection: Choose specific access points and clients for attacks

Deauthentication Attacks: Disrupt connections between devices and access points

Handshake Capture: Capture WPA handshakes for offline cracking

Intuitive Menu System: Easy-to-use interface with color-coded options

Configuration Options: Customize scanning parameters and attack settings

Installation
Ghost-Jammer requires Python 3.x and several dependencies. Follow these steps to install:

sudo apt install python3-pip wireless-tools
sudo pip3 install scapy

Main Menu Options
Scan Networks: Discover nearby WiFi access points

Select Targets: Choose specific networks to target

Start Attack: Launch deauthentication attacks

Capture Handshakes: Capture WPA handshakes for offline cracking

View Scan Results: Review previously scanned networks

Configure Settings: Adjust scanning and attack parameters

Save Scan Results: Export scan data to JSON file

Exit: Quit the application

usage: ghostjammer.py [-h] [-s SKIP] [-i INTERFACE] [-c CHANNEL] [-m MAXIMUM] 
                      [-n] [-t TIMEINTERVAL] [-p PACKETS] [-d] [-a ACCESSPOINT] 
                      [--world]

optional arguments:
  -h, --help            show this help message and exit
  -s SKIP, --skip SKIP  Skip deauthing this MAC address
  -i INTERFACE, --interface INTERFACE
                        Monitor mode interface
  -c CHANNEL, --channel CHANNEL
                        Listen on specific channel
  -m MAXIMUM, --maximum MAXIMUM
                        Max number of clients to deauth
  -n, --noupdate        Don't clear deauth list when max reached
  -t TIMEINTERVAL, --timeinterval TIMEINTERVAL
                        Time interval between packets
  -p PACKETS, --packets PACKETS
                        Number of packets per burst
  -d, --directedonly    Only send to client/AP pairs
  -a ACCESSPOINT, --accesspoint ACCESSPOINT
                        Target specific AP MAC address
  --world               Enable 13 channels mode


  
