# OT-ICS-Industrial-Penetration-Testing-Framework-v2.0
OT/ICS Industrial Penetration Testing Framework v2.0
OT/ICS Industrial Penetration Testing Framework v2.0
Complete Setup, Compilation & Usage Guide

⚠️ LEGAL DISCLAIMER
FOR AUTHORIZED SECURITY TESTING ONLY.
Use only on systems you own or have explicit written permission to test.
Unauthorized use violates computer crime laws (CFAA, Computer Misuse Act, etc.).

SYSTEM REQUIREMENTS

OS: Linux (Ubuntu 20.04+, Kali, Debian, RHEL/CentOS)
Python: 3.8+
RAM: 512MB minimum
Root/sudo: Required for ARP scan and raw socket features

INSTALLATION
Step 1 — Install Python dependencies
bashpip3 install colorama scapy netifaces pymodbus opcua bacpypes
Step 2 — System packages (optional but recommended)
bash# Debian/Ubuntu/Kali
sudo apt-get install -y python3-pip arp-scan nmap tcpdump python3-scapy

# RHEL/CentOS
sudo yum install -y python3-pip tcpdump
Step 3 — Make executable
bashchmod +x ot_framework.py
Step 4 — Run
bash# Interactive mode (recommended)
sudo python3 ot_framework.py

# Or directly
sudo ./ot_framework.py
