#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import socket
import struct
import time
import threading
import subprocess
import json
import hashlib
import binascii
import argparse
import logging
import ipaddress
import random
import signal
import re
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict, OrderedDict
from typing import Optional, List, Dict, Tuple, Any, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
import io

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK & AUTO-INSTALL
# ─────────────────────────────────────────────────────────────────────────────

def check_and_install_deps():
    """Check and install required dependencies."""
    required = {
        'colorama': 'colorama',
        'scapy': 'scapy',
        'netifaces': 'netifaces',
        'pymodbus': 'pymodbus',
        'opcua': 'opcua',
        'bacpypes': 'bacpypes',
    }
    missing = []
    for module, package in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[*] Installing missing dependencies: {', '.join(missing)}")
        for pkg in missing:
            try:
                subprocess.check_call(
                    [sys.executable, '-m', 'pip', 'install', pkg, '-q'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                print(f"[!] Could not install {pkg} - some features may be limited")

check_and_install_deps()

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA = True
except ImportError:
    COLORAMA = False
    class Fore:
        RED=GREEN=YELLOW=BLUE=MAGENTA=CYAN=WHITE=RESET=''
        LIGHTRED_EX=LIGHTGREEN_EX=LIGHTYELLOW_EX=LIGHTBLUE_EX=''
        LIGHTMAGENTA_EX=LIGHTCYAN_EX=LIGHTWHITE_EX=''
    class Back:
        RED=GREEN=YELLOW=BLUE=MAGENTA=CYAN=WHITE=BLACK=RESET=''
    class Style:
        BRIGHT=DIM=NORMAL=RESET_ALL=''

try:
    import netifaces
    NETIFACES = True
except ImportError:
    NETIFACES = False

try:
    from scapy.all import (ARP, Ether, IP, TCP, UDP, ICMP, Raw, srp, sr1,
                            sniff, conf as scapy_conf, get_if_list)
    SCAPY = True
    scapy_conf.verb = 0
except ImportError:
    SCAPY = False

# ─────────────────────────────────────────────────────────────────────────────
# COLOR THEME ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class Colors:
    """Advanced color scheme for OT security framework."""
    # Primary palette
    BANNER      = Fore.CYAN + Style.BRIGHT
    TITLE       = Fore.LIGHTCYAN_EX + Style.BRIGHT
    HEADER      = Fore.YELLOW + Style.BRIGHT
    SUBHEADER   = Fore.LIGHTYELLOW_EX
    
    # Status colors
    SUCCESS     = Fore.LIGHTGREEN_EX + Style.BRIGHT
    INFO        = Fore.LIGHTCYAN_EX
    WARNING     = Fore.LIGHTYELLOW_EX + Style.BRIGHT
    ERROR       = Fore.LIGHTRED_EX + Style.BRIGHT
    CRITICAL    = Fore.RED + Back.BLACK + Style.BRIGHT
    
    # Data colors
    DATA        = Fore.WHITE + Style.BRIGHT
    DATA_DIM    = Fore.WHITE + Style.NORMAL
    IP_ADDR     = Fore.LIGHTMAGENTA_EX + Style.BRIGHT
    PORT        = Fore.LIGHTBLUE_EX + Style.BRIGHT
    PROTO       = Fore.LIGHTCYAN_EX + Style.BRIGHT
    DEVICE      = Fore.LIGHTGREEN_EX
    VULN        = Fore.LIGHTRED_EX + Style.BRIGHT
    NEUTRAL     = Fore.LIGHTWHITE_EX
    
    # Framework UI
    BORDER      = Fore.CYAN
    PROMPT      = Fore.YELLOW + Style.BRIGHT
    MENU_NUM    = Fore.LIGHTCYAN_EX + Style.BRIGHT
    MENU_TEXT   = Fore.WHITE
    SEPARATOR   = Fore.CYAN + Style.DIM
    RESET       = Style.RESET_ALL
    
    # Severity levels
    SEVERITY = {
        'CRITICAL': Fore.RED + Style.BRIGHT,
        'HIGH':     Fore.LIGHTRED_EX + Style.BRIGHT,
        'MEDIUM':   Fore.YELLOW + Style.BRIGHT,
        'LOW':      Fore.LIGHTGREEN_EX,
        'INFO':     Fore.LIGHTCYAN_EX,
        'NONE':     Fore.WHITE,
    }


def cprint(text: str, color: str = '', end: str = '\n'):
    """Colored print wrapper."""
    print(f"{color}{text}{Style.RESET_ALL}", end=end)


def status(msg: str, level: str = 'INFO'):
    """Formatted status message."""
    icons = {
        'INFO':     f"{Colors.BORDER}[{Colors.INFO}*{Colors.BORDER}]{Colors.RESET}",
        'SUCCESS':  f"{Colors.BORDER}[{Colors.SUCCESS}+{Colors.BORDER}]{Colors.RESET}",
        'WARNING':  f"{Colors.BORDER}[{Colors.WARNING}!{Colors.BORDER}]{Colors.RESET}",
        'ERROR':    f"{Colors.BORDER}[{Colors.ERROR}-{Colors.BORDER}]{Colors.RESET}",
        'CRITICAL': f"{Colors.BORDER}[{Colors.CRITICAL}!!{Colors.BORDER}]{Colors.RESET}",
        'VULN':     f"{Colors.BORDER}[{Colors.VULN}VULN{Colors.BORDER}]{Colors.RESET}",
        'SCAN':     f"{Colors.BORDER}[{Colors.PROTO}~{Colors.BORDER}]{Colors.RESET}",
        'DATA':     f"{Colors.BORDER}[{Colors.DATA}>{Colors.BORDER}]{Colors.RESET}",
    }
    icon = icons.get(level, icons['INFO'])
    ts = f"{Colors.SEPARATOR}{datetime.now().strftime('%H:%M:%S')}{Colors.RESET}"
    print(f" {ts} {icon} {msg}")


def print_banner():
    """Print the main framework banner."""
    banner = f"""
{Colors.BANNER}
  ╔═══════════════════════════════════════════════════════════════════════════╗
  ║                                                                           ║
  ║   ██████╗ ████████╗    ██████╗ ███████╗███╗   ██╗    ████████╗███████╗  ║
  ║  ██╔═══██╗╚══██╔══╝    ██╔══██╗██╔════╝████╗  ██║    ╚══██╔══╝██╔════╝  ║
  ║  ██║   ██║   ██║       ██████╔╝█████╗  ██╔██╗ ██║       ██║   █████╗    ║
  ║  ██║   ██║   ██║       ██╔═══╝ ██╔══╝  ██║╚██╗██║       ██║   ██╔══╝   ║
  ║  ╚██████╔╝   ██║       ██║     ███████╗██║ ╚████║       ██║   ██║       ║
  ║   ╚═════╝    ╚═╝       ╚═╝     ╚══════╝╚═╝  ╚═══╝       ╚═╝   ╚═╝       ║
  ║                                                                           ║
{Colors.TITLE}  ║         OT/ICS INDUSTRIAL PENETRATION TESTING FRAMEWORK v2.0            ║
{Colors.WARNING}  ║              Advanced Industrial Security Assessment Platform             ║
{Colors.ERROR}  ║              ⚠  FOR AUTHORIZED SECURITY TESTING ONLY  ⚠                 ║
{Colors.BANNER}  ╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

  {Colors.INFO}Protocols:{Colors.RESET} Modbus · DNP3 · IEC104 · IEC61850 · OPC-UA · BACnet · EtherNet/IP
  {Colors.INFO}Targets:{Colors.RESET}   PLC · RTU · HMI · SCADA · IIoT · Industrial Switches
  {Colors.WARNING}Platform:{Colors.RESET}  Linux x86_64 · Python 3.8+
"""
    print(banner)


def print_section(title: str, width: int = 75):
    """Print a formatted section header."""
    line = '─' * width
    print(f"\n{Colors.BORDER}  ╭{line}╮")
    pad = (width - len(title) - 2) // 2
    print(f"  │{' ' * pad} {Colors.HEADER}{title}{Colors.BORDER}{' ' * (width - pad - len(title) - 1)}│")
    print(f"  ╰{line}╯{Colors.RESET}\n")


def print_table(headers: List[str], rows: List[List[str]], 
                col_colors: Optional[List[str]] = None):
    """Print a formatted table."""
    if not rows:
        return
    
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))
    
    sep = f"{Colors.BORDER}  ├" + "┼".join("─" * (w + 2) for w in col_widths) + f"┤{Colors.RESET}"
    top = f"{Colors.BORDER}  ┌" + "┬".join("─" * (w + 2) for w in col_widths) + f"┐{Colors.RESET}"
    bot = f"{Colors.BORDER}  └" + "┴".join("─" * (w + 2) for w in col_widths) + f"┘{Colors.RESET}"
    
    print(top)
    # Header row
    header_cells = []
    for i, (h, w) in enumerate(zip(headers, col_widths)):
        header_cells.append(f" {Colors.HEADER}{h:<{w}}{Colors.BORDER} ")
    print(f"{Colors.BORDER}  │{'│'.join(header_cells)}│{Colors.RESET}")
    print(sep)
    
    # Data rows
    for row in rows:
        cells = []
        for i, (cell, w) in enumerate(zip(row, col_widths)):
            color = col_colors[i] if col_colors and i < len(col_colors) else Colors.DATA_DIM
            cells.append(f" {color}{str(cell):<{w}}{Colors.BORDER} ")
        print(f"{Colors.BORDER}  │{'│'.join(cells)}│{Colors.RESET}")
    print(bot)


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

class DeviceType(Enum):
    PLC       = "PLC"
    RTU       = "RTU"
    HMI       = "HMI"
    SCADA     = "SCADA Server"
    IED       = "IED"
    SWITCH    = "Industrial Switch"
    IIOT      = "IIoT Device"
    HISTORIAN = "Historian"
    GATEWAY   = "Protocol Gateway"
    UNKNOWN   = "Unknown"


class Severity(Enum):
    CRITICAL = 5
    HIGH     = 4
    MEDIUM   = 3
    LOW      = 2
    INFO     = 1
    NONE     = 0


@dataclass
class NetworkService:
    port:     int
    protocol: str
    service:  str
    banner:   str = ""
    version:  str = ""
    state:    str = "open"


@dataclass
class IndustrialDevice:
    ip:          str
    mac:         str         = ""
    hostname:    str         = ""
    device_type: DeviceType  = DeviceType.UNKNOWN
    vendor:      str         = ""
    model:       str         = ""
    firmware:    str         = ""
    os:          str         = ""
    services:    List[NetworkService] = field(default_factory=list)
    protocols:   List[str]   = field(default_factory=list)
    tags:        List[str]   = field(default_factory=list)
    first_seen:  str         = field(default_factory=lambda: datetime.now().isoformat())
    last_seen:   str         = field(default_factory=lambda: datetime.now().isoformat())
    location:    str         = ""
    notes:       str         = ""

    def to_dict(self):
        d = asdict(self)
        d['device_type'] = self.device_type.value
        return d


@dataclass
class Vulnerability:
    vuln_id:     str
    title:       str
    severity:    Severity
    device_ip:   str
    description: str
    cvss:        float        = 0.0
    cve:         str         = ""
    remediation: str         = ""
    evidence:    str         = ""
    protocol:    str         = ""
    timestamp:   str         = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        d = asdict(self)
        d['severity'] = self.severity.name
        return d


@dataclass
class ProtocolResult:
    protocol:   str
    target:     str
    port:       int
    success:    bool
    data:       Dict[str, Any]  = field(default_factory=dict)
    raw_bytes:  bytes           = b""
    error:      str             = ""
    timestamp:  str             = field(default_factory=lambda: datetime.now().isoformat())


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SYSTEM
# ─────────────────────────────────────────────────────────────────────────────

class FrameworkLogger:
    def __init__(self, log_file: str = "ot_framework.log", verbose: bool = False):
        self.verbose   = verbose
        self.log_file  = log_file
        self._lock     = threading.Lock()
        
        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('OTFramework')
    
    def info(self, msg: str):
        self.logger.info(msg)
        if self.verbose:
            status(msg, 'INFO')
    
    def success(self, msg: str):
        self.logger.info(f"[SUCCESS] {msg}")
        status(msg, 'SUCCESS')
    
    def warn(self, msg: str):
        self.logger.warning(msg)
        status(msg, 'WARNING')
    
    def error(self, msg: str):
        self.logger.error(msg)
        status(msg, 'ERROR')
    
    def vuln(self, msg: str):
        self.logger.critical(f"[VULN] {msg}")
        status(msg, 'VULN')
    
    def scan(self, msg: str):
        self.logger.debug(f"[SCAN] {msg}")
        if self.verbose:
            status(msg, 'SCAN')


# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINT DATABASE
# ─────────────────────────────────────────────────────────────────────────────

class FingerprintDB:
    """Industrial device fingerprint signatures database."""
    
    # OUI → Vendor mapping (industrial vendors)
    OUI_DB: Dict[str, str] = {
        '00:0E:8C': 'Siemens AG',
        '00:1B:1B': 'Siemens AG',
        '00:1C:06': 'Siemens AG',
        '08:00:06': 'Siemens AG',
        '00:00:E2': 'Siemens AG',
        '00:E0:4C': 'Realtek (IIoT)',
        '00:80:A3': 'Lantronix',
        '00:20:4A': 'Schneider Electric',
        '00:80:F4': 'Schneider Electric',
        '00:00:54': 'Schneider Electric',
        '00:0A:E6': 'Schneider Electric',
        '00:50:C2': 'Rockwell Automation',
        '00:00:BC': 'Rockwell/Allen-Bradley',
        '00:1D:9C': 'Rockwell Automation',
        '00:00:54': 'Yokogawa',
        '00:02:D1': 'Honeywell',
        '00:0A:CC': 'Mitsubishi Electric',
        '00:1E:13': 'GE Automation',
        '00:00:A2': 'ABB',
        '00:30:DE': 'ABB',
        '00:0C:DB': 'Emerson Electric',
        '00:60:35': 'Advantech',
        '00:D0:C9': 'Moxa Technologies',
        '00:90:E8': 'Moxa Technologies',
        '00:60:65': 'Wago',
        '00:30:64': 'Phoenix Contact',
        '00:1B:97': 'Phoenix Contact',
        '50:FF:20': 'Beckhoff Automation',
        '00:01:05': 'Danfoss',
        '00:0B:AB': 'Pilz GmbH',
        '00:0C:EB': 'Pepperl+Fuchs',
    }
    
    # Port → Protocol/Service mapping (ICS-specific)
    PORT_PROTO: Dict[int, Dict] = {
        # Modbus
        502:   {'proto': 'Modbus TCP',      'type': 'PLC/RTU',  'risk': 'HIGH'},
        # DNP3
        20000: {'proto': 'DNP3',            'type': 'RTU',      'risk': 'HIGH'},
        19999: {'proto': 'DNP3 TLS',        'type': 'RTU',      'risk': 'MEDIUM'},
        # IEC 60870-5-104
        2404:  {'proto': 'IEC 60870-5-104', 'type': 'RTU/IED',  'risk': 'HIGH'},
        # IEC 61850
        102:   {'proto': 'IEC 61850/MMS',   'type': 'IED',      'risk': 'HIGH'},
        # OPC
        135:   {'proto': 'OPC DA (DCOM)',    'type': 'SCADA',    'risk': 'CRITICAL'},
        4840:  {'proto': 'OPC UA',          'type': 'SCADA',    'risk': 'MEDIUM'},
        # BACnet
        47808: {'proto': 'BACnet/IP',       'type': 'BMS',      'risk': 'MEDIUM'},
        # EtherNet/IP / CIP
        44818: {'proto': 'EtherNet/IP',     'type': 'PLC',      'risk': 'HIGH'},
        2222:  {'proto': 'EtherNet/IP UDP', 'type': 'PLC',      'risk': 'HIGH'},
        # Profinet
        34964: {'proto': 'Profinet',        'type': 'PLC',      'risk': 'HIGH'},
        # S7 (Siemens)
        102:   {'proto': 'S7/TPKT',        'type': 'PLC',      'risk': 'CRITICAL'},
        # MQTT (IIoT)
        1883:  {'proto': 'MQTT',           'type': 'IIoT',     'risk': 'HIGH'},
        8883:  {'proto': 'MQTT TLS',       'type': 'IIoT',     'risk': 'MEDIUM'},
        # Web interfaces
        80:    {'proto': 'HTTP',           'type': 'HMI/Web',  'risk': 'MEDIUM'},
        443:   {'proto': 'HTTPS',          'type': 'HMI/Web',  'risk': 'LOW'},
        8080:  {'proto': 'HTTP-Alt',       'type': 'HMI',      'risk': 'MEDIUM'},
        8443:  {'proto': 'HTTPS-Alt',      'type': 'HMI',      'risk': 'LOW'},
        # Serial/Legacy
        23:    {'proto': 'Telnet',         'type': 'Legacy',   'risk': 'CRITICAL'},
        21:    {'proto': 'FTP',            'type': 'Firmware', 'risk': 'HIGH'},
        22:    {'proto': 'SSH',            'type': 'Mgmt',     'risk': 'LOW'},
        # SNMP
        161:   {'proto': 'SNMP',           'type': 'Network',  'risk': 'HIGH'},
        162:   {'proto': 'SNMP Trap',      'type': 'Network',  'risk': 'MEDIUM'},
        # SCADA/Historian
        1962:  {'proto': 'PCWorx',         'type': 'PLC',      'risk': 'CRITICAL'},
        9600:  {'proto': 'OMRON FINS',     'type': 'PLC',      'risk': 'HIGH'},
        5006:  {'proto': 'Mitsubishi MELSEC','type': 'PLC',    'risk': 'HIGH'},
        5007:  {'proto': 'Mitsubishi MELSEC','type': 'PLC',    'risk': 'HIGH'},
        18245: {'proto': 'GE SRTP',        'type': 'PLC',      'risk': 'HIGH'},
        18246: {'proto': 'GE SRTP',        'type': 'PLC',      'risk': 'HIGH'},
        # M-Bus
        2351:  {'proto': 'M-Bus',          'type': 'Meter',    'risk': 'MEDIUM'},
        # CAN Bus gateway
        6550:  {'proto': 'CAN Bus Gateway', 'type': 'IIoT',   'risk': 'MEDIUM'},
    }
    
    # Banner/Response → Device fingerprints
    BANNERS: List[Dict] = [
        {'pattern': r'[Ss]iemens',       'vendor': 'Siemens',         'type': DeviceType.PLC},
        {'pattern': r'STEP.?7|S7-\d00',  'vendor': 'Siemens',         'type': DeviceType.PLC},
        {'pattern': r'[Aa]llen.[Bb]radley|Logix|ControlLogix|MicroLogix',
                                          'vendor': 'Rockwell',        'type': DeviceType.PLC},
        {'pattern': r'[Ss]chneider|Modicon|Quantum|Premium|M340',
                                          'vendor': 'Schneider Electric','type': DeviceType.PLC},
        {'pattern': r'[Gg][Ee].[Ff]anuc|GE PLC|FANUC',
                                          'vendor': 'GE Automation',   'type': DeviceType.PLC},
        {'pattern': r'Mitsubishi|MELSEC', 'vendor': 'Mitsubishi',      'type': DeviceType.PLC},
        {'pattern': r'[Oo]mron|FINS',     'vendor': 'Omron',           'type': DeviceType.PLC},
        {'pattern': r'[Aa][Bb][Bb]',      'vendor': 'ABB',             'type': DeviceType.PLC},
        {'pattern': r'[Hh]oneywell',      'vendor': 'Honeywell',       'type': DeviceType.SCADA},
        {'pattern': r'[Ee]merson|DeltaV', 'vendor': 'Emerson',         'type': DeviceType.SCADA},
        {'pattern': r'[Ww][Ii]nCC|WinCC', 'vendor': 'Siemens',         'type': DeviceType.HMI},
        {'pattern': r'[Ff]actor[Yy][Tt]alk|FactoryTalk',
                                          'vendor': 'Rockwell',        'type': DeviceType.HMI},
        {'pattern': r'[Ii]gnition',       'vendor': 'Inductive Automation','type': DeviceType.SCADA},
        {'pattern': r'[Mm]oxa',           'vendor': 'Moxa',            'type': DeviceType.GATEWAY},
        {'pattern': r'[Aa]dvantec',       'vendor': 'Advantech',       'type': DeviceType.IIOT},
        {'pattern': r'[Bb]eckhoff|TwinCAT','vendor': 'Beckhoff',       'type': DeviceType.PLC},
        {'pattern': r'[Ww][Aa][Gg][Oo]', 'vendor': 'WAGO',            'type': DeviceType.PLC},
        {'pattern': r'[Pp]hoenix.?[Cc]ontact',
                                          'vendor': 'Phoenix Contact', 'type': DeviceType.PLC},
        {'pattern': r'[Cc]isco|Catalyst|IOS',
                                          'vendor': 'Cisco',           'type': DeviceType.SWITCH},
        {'pattern': r'[Hh][Ii]rschmann',  'vendor': 'Hirschmann',      'type': DeviceType.SWITCH},
        {'pattern': r'[Ss][Ee]imens RUGGEDCOM',
                                          'vendor': 'Siemens',         'type': DeviceType.SWITCH},
    ]


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 1: ASSET DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

class AssetDiscovery:
    """Industrial asset discovery and network enumeration."""
    
    def __init__(self, logger: FrameworkLogger, timeout: float = 2.0,
                 threads: int = 50):
        self.logger   = logger
        self.timeout  = timeout
        self.threads  = threads
        self.devices: Dict[str, IndustrialDevice] = {}
        self._lock    = threading.Lock()
        self.fpdb     = FingerprintDB()
    
    def ping_sweep(self, network: str) -> List[str]:
        """ICMP ping sweep using socket (no root required fallback)."""
        alive = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
        except ValueError as e:
            self.logger.error(f"Invalid network: {e}")
            return alive
        
        status(f"Ping sweep: {network} ({len(hosts)} hosts)", 'SCAN')
        
        def ping_host(ip: str) -> Optional[str]:
            """Attempt to reach host via TCP (port 80) if ICMP unavailable."""
            try:
                # Try ICMP via subprocess (works without scapy)
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', str(ip)],
                    capture_output=True, timeout=2
                )
                if result.returncode == 0:
                    return str(ip)
            except Exception:
                pass
            # Fallback: TCP connect to common port
            for port in [80, 102, 502, 22, 23]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((str(ip), port)) == 0:
                        s.close()
                        return str(ip)
                    s.close()
                except Exception:
                    pass
            return None
        
        bar_width = 40
        total = len(hosts)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(ping_host, str(ip)): str(ip) for ip in hosts}
            done = 0
            for future in as_completed(futures):
                done += 1
                result = future.result()
                if result:
                    alive.append(result)
                    print(f"\r  {Colors.SCAN if hasattr(Colors,'SCAN') else ''}"
                          f"[{Colors.SUCCESS}+{Colors.RESET}] Found: {Colors.IP_ADDR}{result}{Colors.RESET}"
                          f"  [{done}/{total}]", end='')
                else:
                    pct = done / total
                    filled = int(bar_width * pct)
                    bar = f"{'█' * filled}{'░' * (bar_width - filled)}"
                    print(f"\r  {Colors.BORDER}[{Colors.INFO}{bar}{Colors.BORDER}]{Colors.RESET}"
                          f" {done}/{total}", end='')
                sys.stdout.flush()
        
        print()
        status(f"Discovered {len(alive)} live hosts", 'SUCCESS')
        return sorted(alive)
    
    def arp_scan(self, interface: str = None, network: str = None) -> List[Tuple[str, str]]:
        """ARP scan using scapy (requires root) or system arp-scan."""
        results = []
        
        if SCAPY:
            try:
                target = network or "192.168.1.0/24"
                status(f"ARP scan on {target}", 'SCAN')
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
                             timeout=self.timeout, verbose=False, iface=interface)
                for _, rcv in ans:
                    results.append((rcv.psrc, rcv.hwsrc))
                    status(f"ARP: {rcv.psrc:16s}  {rcv.hwsrc}", 'SUCCESS')
            except Exception as e:
                self.logger.warn(f"ARP scan failed: {e}")
        
        # Fallback: system arp-scan
        if not results:
            try:
                cmd = ['arp-scan', '-l'] if not network else ['arp-scan', network]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                for line in result.stdout.splitlines():
                    m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)', line, re.I)
                    if m:
                        results.append((m.group(1), m.group(2)))
            except Exception:
                pass
        
        # Fallback: read system ARP cache
        if not results:
            try:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)', line, re.I)
                    if m:
                        results.append((m.group(1), m.group(2)))
            except Exception:
                pass
        
        return results
    
    def port_scan(self, ip: str, ports: Optional[List[int]] = None,
                  full: bool = False) -> List[NetworkService]:
        """TCP port scanner with banner grabbing."""
        if ports is None:
            if full:
                ports = list(range(1, 65536))
            else:
                # OT/ICS + common ports
                ports = sorted(set(
                    list(self.fpdb.PORT_PROTO.keys()) +
                    [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080, 8443,
                     3389, 5900, 4840, 34980, 34962, 34963, 34964]
                ))
        
        services = []
        
        def scan_port(port: int) -> Optional[NetworkService]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((ip, port)) == 0:
                    banner = ""
                    try:
                        s.send(b'\r\n')
                        data = s.recv(1024)
                        banner = data.decode('utf-8', errors='replace').strip()
                    except Exception:
                        pass
                    s.close()
                    
                    proto_info = self.fpdb.PORT_PROTO.get(port, {})
                    proto = proto_info.get('proto', 'unknown')
                    svc_type = proto_info.get('type', 'unknown')
                    
                    return NetworkService(
                        port=port, protocol='TCP',
                        service=f"{proto} ({svc_type})" if svc_type != 'unknown' else proto,
                        banner=banner[:200]
                    )
                s.close()
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=min(self.threads, 200)) as executor:
            futures = {executor.submit(scan_port, p): p for p in ports}
            for future in as_completed(futures):
                svc = future.result()
                if svc:
                    services.append(svc)
                    self.logger.scan(f"{ip}:{svc.port} - {svc.service}")
        
        return sorted(services, key=lambda s: s.port)
    
    def udp_scan(self, ip: str, ports: Optional[List[int]] = None) -> List[NetworkService]:
        """UDP scan for ICS protocols."""
        if ports is None:
            ports = [47808, 2222, 161, 162, 5353, 67, 68]  # BACnet, EIP, SNMP, mDNS, DHCP
        
        services = []
        
        def scan_udp(port: int) -> Optional[NetworkService]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(self.timeout)
                # Send protocol-specific probe
                probe = self._get_udp_probe(port)
                s.sendto(probe, (ip, port))
                try:
                    data, _ = s.recvfrom(1024)
                    proto_info = self.fpdb.PORT_PROTO.get(port, {})
                    return NetworkService(
                        port=port, protocol='UDP',
                        service=proto_info.get('proto', 'unknown'),
                        banner=binascii.hexlify(data[:32]).decode()
                    )
                except socket.timeout:
                    pass
                s.close()
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan_udp, p) for p in ports]
            for future in as_completed(futures):
                svc = future.result()
                if svc:
                    services.append(svc)
        
        return services
    
    def _get_udp_probe(self, port: int) -> bytes:
        """Return protocol-specific UDP probe packet."""
        probes = {
            47808: bytes([0x81, 0x0b, 0x00, 0x0c, 0x01, 0x04, 0x00, 0x05,
                          0x0a, 0x05, 0x01, 0x01]),  # BACnet WhoIs
            161:   bytes([0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
                          0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19]),  # SNMP GetRequest
            2222:  bytes([0x65, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),  # EtherNet/IP list
        }
        return probes.get(port, b'\x00\x00')
    
    def fingerprint_device(self, ip: str, device: IndustrialDevice) -> IndustrialDevice:
        """Fingerprint device based on open ports, banners, and protocol responses."""
        # MAC → Vendor
        mac_prefix = ':'.join(device.mac.split(':')[:3]).upper() if device.mac else ''
        for oui, vendor in self.fpdb.OUI_DB.items():
            if mac_prefix.upper() == oui.upper():
                device.vendor = vendor
                break
        
        # Port-based device type detection
        open_ports = {s.port for s in device.services}
        port_types = []
        for port in open_ports:
            if port in self.fpdb.PORT_PROTO:
                port_types.append(self.fpdb.PORT_PROTO[port]['type'])
                device.protocols.append(self.fpdb.PORT_PROTO[port]['proto'])
        
        device.protocols = list(set(device.protocols))
        
        # Determine device type from ports
        type_priority = {
            'PLC': DeviceType.PLC, 'RTU': DeviceType.RTU, 'HMI': DeviceType.HMI,
            'SCADA': DeviceType.SCADA, 'IED': DeviceType.IED,
            'IIoT': DeviceType.IIOT, 'Network': DeviceType.SWITCH
        }
        for t, dtype in type_priority.items():
            if any(t in pt for pt in port_types):
                device.device_type = dtype
                break
        
        # Banner-based fingerprinting
        all_banners = ' '.join(s.banner for s in device.services if s.banner)
        for fp in self.fpdb.BANNERS:
            if re.search(fp['pattern'], all_banners, re.I):
                if not device.vendor:
                    device.vendor = fp['vendor']
                device.device_type = fp['type']
                break
        
        # S7 detection (port 102 with specific fingerprint)
        if 102 in open_ports:
            if not device.vendor:
                device.vendor = 'Siemens (probable)'
            device.device_type = DeviceType.PLC
            device.protocols.append('S7/TPKT')
        
        # Hostname resolution
        try:
            device.hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        
        return device
    
    def discover_network(self, network: str, interface: str = None,
                         full_scan: bool = False) -> Dict[str, IndustrialDevice]:
        """Full network discovery pipeline."""
        print_section("ASSET DISCOVERY")
        
        # Step 1: ARP scan
        status("Phase 1: ARP Scan", 'INFO')
        arp_results = self.arp_scan(interface=interface, network=network)
        
        # Step 2: Ping sweep
        status("Phase 2: ICMP/TCP Ping Sweep", 'INFO')
        alive_hosts = self.ping_sweep(network)
        
        # Merge results
        all_hosts = set(alive_hosts)
        mac_map = {}
        for ip, mac in arp_results:
            all_hosts.add(ip)
            mac_map[ip] = mac
        
        status(f"Total unique hosts: {Colors.DATA}{len(all_hosts)}{Colors.RESET}", 'SUCCESS')
        
        if not all_hosts:
            status("No hosts discovered. Try a different network range.", 'WARNING')
            return {}
        
        # Step 3: Port scan each host
        status("Phase 3: Service Discovery & Port Scanning", 'INFO')
        
        for i, ip in enumerate(sorted(all_hosts)):
            print(f"\n  {Colors.BORDER}┌─ {Colors.IP_ADDR}{ip}{Colors.RESET} "
                  f"({Colors.DATA}{i+1}/{len(all_hosts)}{Colors.RESET})")
            
            device = IndustrialDevice(ip=ip, mac=mac_map.get(ip, ''))
            
            # TCP scan
            services = self.port_scan(ip, full=full_scan)
            device.services = services
            
            # UDP scan for ICS protocols
            udp_services = self.udp_scan(ip)
            device.services.extend(udp_services)
            
            # Fingerprint
            device = self.fingerprint_device(ip, device)
            
            # Display result
            dtype_color = {
                DeviceType.PLC: Colors.CRITICAL,
                DeviceType.RTU: Colors.ERROR,
                DeviceType.HMI: Colors.WARNING,
                DeviceType.SCADA: Colors.ERROR,
                DeviceType.SWITCH: Colors.INFO,
                DeviceType.IIOT: Colors.INFO,
            }.get(device.device_type, Colors.NEUTRAL)
            
            print(f"  {Colors.BORDER}│  Type:{Colors.RESET} "
                  f"{dtype_color}{device.device_type.value}{Colors.RESET}")
            if device.vendor:
                print(f"  {Colors.BORDER}│  Vendor:{Colors.RESET} "
                      f"{Colors.DEVICE}{device.vendor}{Colors.RESET}")
            if device.protocols:
                print(f"  {Colors.BORDER}│  Protocols:{Colors.RESET} "
                      f"{Colors.PROTO}{', '.join(device.protocols)}{Colors.RESET}")
            if services:
                port_str = ', '.join(f"{s.port}/{s.protocol}" for s in services[:8])
                if len(services) > 8:
                    port_str += f" (+{len(services)-8} more)"
                print(f"  {Colors.BORDER}│  Open Ports:{Colors.RESET} "
                      f"{Colors.PORT}{port_str}{Colors.RESET}")
            print(f"  {Colors.BORDER}└{'─'*50}")
            
            self.devices[ip] = device
        
        return self.devices
    
    def passive_inventory(self, interface: str, duration: int = 60) -> Dict[str, IndustrialDevice]:
        """Passive network monitoring for asset inventory (no active probing)."""
        print_section("PASSIVE ASSET INVENTORY")
        
        if not SCAPY:
            status("Scapy not available. Using tcpdump fallback.", 'WARNING')
            return self._passive_tcpdump(interface, duration)
        
        status(f"Passive capture on {interface} for {duration}s (read-only, no probes)", 'INFO')
        
        seen: Dict[str, set] = defaultdict(set)
        
        def pkt_handler(pkt):
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                seen[src].add(dst)
                if TCP in pkt and pkt[TCP].flags & 0x02:  # SYN
                    dport = pkt[TCP].dport
                    if dport in self.fpdb.PORT_PROTO:
                        if dst not in self.devices:
                            dev = IndustrialDevice(ip=dst)
                            proto = self.fpdb.PORT_PROTO[dport]['proto']
                            dev.protocols.append(proto)
                            self.devices[dst] = dev
                            self.logger.info(f"Passive: {dst} - {proto} traffic observed")
        
        try:
            sniff(iface=interface, prn=pkt_handler, timeout=duration, store=False)
        except Exception as e:
            self.logger.error(f"Passive capture error: {e}")
        
        status(f"Passive capture complete. {len(self.devices)} devices observed.", 'SUCCESS')
        return self.devices
    
    def _passive_tcpdump(self, interface: str, duration: int) -> Dict[str, IndustrialDevice]:
        """Fallback passive capture using tcpdump."""
        try:
            ics_ports = ','.join(str(p) for p in self.fpdb.PORT_PROTO.keys())
            cmd = ['tcpdump', '-i', interface, '-nn', f'-G', str(duration),
                   '-W', '1', '-w', '/tmp/ot_capture.pcap', f'port {" or port ".join(ics_ports.split(",")[:10])}']
            subprocess.run(cmd[:8], timeout=duration + 5, capture_output=True)
        except Exception as e:
            self.logger.error(f"tcpdump error: {e}")
        return self.devices
    
    def topology_map(self) -> str:
        """Generate ASCII network topology map."""
        print_section("NETWORK TOPOLOGY MAP")
        
        if not self.devices:
            return "No devices discovered yet."
        
        # Group by subnet
        subnets: Dict[str, List[IndustrialDevice]] = defaultdict(list)
        for ip, dev in self.devices.items():
            try:
                subnet = '.'.join(ip.split('.')[:3]) + '.x'
            except Exception:
                subnet = 'unknown'
            subnets[subnet].append(dev)
        
        output = []
        output.append(f"\n  {Colors.BORDER}[INTERNET/WAN]{Colors.RESET}")
        output.append(f"       │")
        output.append(f"  {Colors.BORDER}[FIREWALL/DMZ]{Colors.RESET}")
        output.append(f"       │")
        
        for subnet, devs in subnets.items():
            output.append(f"  {Colors.INFO}[{subnet}]{Colors.RESET}")
            for i, dev in enumerate(devs):
                prefix = "  └─" if i == len(devs) - 1 else "  ├─"
                dtype_color = Colors.WARNING if dev.device_type in [DeviceType.PLC, DeviceType.RTU] else Colors.INFO
                output.append(
                    f"  {prefix} {Colors.IP_ADDR}{dev.ip:16s}{Colors.RESET} "
                    f"{dtype_color}{dev.device_type.value:20s}{Colors.RESET} "
                    f"{Colors.DEVICE}{dev.vendor or 'Unknown':20s}{Colors.RESET} "
                    f"{Colors.PROTO}{', '.join(dev.protocols[:3])}{Colors.RESET}"
                )
        
        topo = '\n'.join(output)
        print(topo)
        return topo


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 2: INDUSTRIAL PROTOCOL ANALYZERS
# ─────────────────────────────────────────────────────────────────────────────

class ModbusTCPAnalyzer:
    """Modbus TCP protocol analyzer and security tester."""
    
    FUNCTION_CODES = {
        0x01: 'Read Coils',
        0x02: 'Read Discrete Inputs',
        0x03: 'Read Holding Registers',
        0x04: 'Read Input Registers',
        0x05: 'Write Single Coil',
        0x06: 'Write Single Register',
        0x0F: 'Write Multiple Coils',
        0x10: 'Write Multiple Registers',
        0x14: 'Read File Record',
        0x15: 'Write File Record',
        0x16: 'Mask Write Register',
        0x17: 'Read/Write Multiple Registers',
        0x18: 'Read FIFO Queue',
        0x2B: 'Encapsulated Interface Transport (MEI)',
    }
    
    def __init__(self, host: str, port: int = 502, timeout: float = 3.0,
                 unit_id: int = 1):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.unit_id = unit_id
        self.sock    = None
        self.trans_id = 0
    
    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            return False
    
    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
    
    def _build_mbap(self, pdu: bytes, unit_id: int = None) -> bytes:
        """Build Modbus Application Protocol Header."""
        self.trans_id += 1
        uid = unit_id if unit_id is not None else self.unit_id
        # Transaction ID (2), Protocol ID (2=0x0000), Length (2), Unit ID (1)
        mbap = struct.pack('>HHH', self.trans_id, 0x0000, len(pdu) + 1)
        return mbap + bytes([uid]) + pdu
    
    def _send_recv(self, pdu: bytes, unit_id: int = None) -> Optional[bytes]:
        try:
            packet = self._build_mbap(pdu, unit_id)
            self.sock.send(packet)
            resp = self.sock.recv(260)
            if len(resp) >= 8:
                return resp[7:]  # Strip MBAP + unit ID
            return resp
        except Exception:
            return None
    
    def read_device_identification(self) -> Dict:
        """MEI Read Device Identification (FC 0x2B/0x0E)."""
        results = {}
        if not self.sock:
            return results
        
        # Object IDs: 0=VendorName, 1=ProductCode, 2=MajorMinorRevision,
        #             3=VendorURL, 4=ProductName, 5=ModelName, 6=UserAppName
        for obj_id in range(7):
            pdu = bytes([0x2B, 0x0E, 0x01, obj_id])
            resp = self._send_recv(pdu)
            if resp and len(resp) >= 6 and resp[0] == 0x2B:
                # Parse MEI response
                num_obj = resp[5] if len(resp) > 5 else 0
                offset = 6
                for _ in range(num_obj):
                    if offset + 2 > len(resp):
                        break
                    oid = resp[offset]
                    olen = resp[offset + 1]
                    if offset + 2 + olen <= len(resp):
                        val = resp[offset + 2:offset + 2 + olen].decode('utf-8', errors='replace')
                        key_map = {
                            0: 'VendorName', 1: 'ProductCode', 2: 'Revision',
                            3: 'VendorURL', 4: 'ProductName', 5: 'ModelName',
                            6: 'ApplicationName'
                        }
                        results[key_map.get(oid, f'Object_{oid}')] = val
                    offset += 2 + olen
        return results
    
    def read_holding_registers(self, start: int = 0, count: int = 10,
                                unit_id: int = None) -> Optional[List[int]]:
        """Read Holding Registers (FC 0x03)."""
        if not self.sock:
            return None
        count = min(count, 125)  # Max per request
        pdu = struct.pack('>BHH', 0x03, start, count)
        resp = self._send_recv(pdu, unit_id)
        if resp and resp[0] == 0x03 and len(resp) >= 2:
            byte_count = resp[1]
            values = []
            for i in range(0, byte_count, 2):
                if 2 + i + 1 < len(resp):
                    values.append(struct.unpack('>H', resp[2+i:4+i])[0])
            return values
        return None
    
    def read_coils(self, start: int = 0, count: int = 16,
                   unit_id: int = None) -> Optional[List[bool]]:
        """Read Coils (FC 0x01)."""
        if not self.sock:
            return None
        count = min(count, 2000)
        pdu = struct.pack('>BHH', 0x01, start, count)
        resp = self._send_recv(pdu, unit_id)
        if resp and resp[0] == 0x01:
            coils = []
            for byte in resp[2:2 + resp[1]]:
                for bit in range(8):
                    coils.append(bool(byte & (1 << bit)))
            return coils[:count]
        return None
    
    def scan_unit_ids(self, max_uid: int = 247) -> List[int]:
        """Scan for valid Modbus Unit IDs (slave IDs)."""
        active = []
        for uid in range(0, max_uid + 1):
            pdu = struct.pack('>BHH', 0x03, 0, 1)
            resp = self._send_recv(pdu, uid)
            if resp and resp[0] in [0x03, 0x83]:  # 0x83 = exception response
                active.append(uid)
        return active
    
    def check_write_access(self) -> Dict[str, bool]:
        """Test for unauthorized write access (CRITICAL security check)."""
        results = {}
        
        # Try writing to register 0 with same value (read-modify-write to be safe)
        regs = self.read_holding_registers(0, 1)
        if regs is not None:
            original = regs[0]
            # Try writing back same value
            pdu = struct.pack('>BHH', 0x06, 0x0000, original)
            resp = self._send_recv(pdu)
            if resp and resp[0] == 0x06:
                results['write_registers'] = True
            elif resp and resp[0] == 0x86:
                results['write_registers'] = False
            else:
                results['write_registers'] = None
        
        # Try writing coil
        pdu = struct.pack('>BHH', 0x05, 0x0000, 0x0000)  # Write coil OFF
        resp = self._send_recv(pdu)
        if resp:
            results['write_coils'] = resp[0] == 0x05
        
        return results
    
    def full_assessment(self) -> ProtocolResult:
        """Complete Modbus security assessment."""
        result = ProtocolResult(protocol='Modbus TCP', target=self.host, port=self.port,
                                success=False, data={})
        
        if not self.connect():
            result.error = "Connection refused"
            return result
        
        result.success = True
        data = result.data
        
        # Device identification
        status(f"Modbus: Reading device identification from {self.host}:{self.port}", 'SCAN')
        device_info = self.read_device_identification()
        if device_info:
            data['device_identification'] = device_info
            status(f"Device: {device_info}", 'SUCCESS')
        
        # Read registers
        status("Modbus: Reading holding registers (0-49)", 'SCAN')
        regs = self.read_holding_registers(0, 50)
        if regs:
            data['holding_registers_0_49'] = regs
            status(f"Holding Registers[0:50]: {regs[:10]}...", 'DATA')
        
        # Read coils
        coils = self.read_coils(0, 32)
        if coils:
            data['coils_0_31'] = coils
        
        # Scan unit IDs
        status("Modbus: Scanning Unit IDs", 'SCAN')
        uids = self.scan_unit_ids(16)
        if uids:
            data['active_unit_ids'] = uids
            status(f"Active Unit IDs: {uids}", 'SUCCESS')
        
        # Write access check
        status("Modbus: Testing write access (SECURITY CHECK)", 'SCAN')
        write_access = self.check_write_access()
        data['write_access'] = write_access
        if write_access.get('write_registers'):
            status(f"UNAUTHORIZED WRITE ACCESS to {self.host}!", 'VULN')
        
        self.disconnect()
        return result


class DNP3Analyzer:
    """DNP3 protocol analyzer."""
    
    DNP3_PORT = 20000
    
    # DNP3 Application Layer Function Codes
    FUNCTION_CODES = {
        0x00: 'Confirm', 0x01: 'Read', 0x02: 'Write',
        0x03: 'Select', 0x04: 'Operate', 0x05: 'Direct Operate',
        0x06: 'Direct Operate No Ack', 0x07: 'Immed Freeze',
        0x08: 'Immed Freeze No Ack', 0x09: 'Freeze Clear',
        0x0A: 'Freeze Clear No Ack', 0x0B: 'Freeze At Time',
        0x0C: 'Freeze At Time No Ack', 0x0D: 'Cold Restart',
        0x0E: 'Warm Restart', 0x0F: 'Initialize Data',
        0x10: 'Initialize Application', 0x11: 'Start Application',
        0x12: 'Stop Application', 0x13: 'Save Configuration',
        0x14: 'Enable Unsolicited', 0x15: 'Disable Unsolicited',
        0x16: 'Assign Class', 0x17: 'Delay Measurement',
        0x18: 'Record Current Time', 0x81: 'Response',
        0x82: 'Unsolicited Response',
    }
    
    def __init__(self, host: str, port: int = 20000, timeout: float = 3.0,
                 src_addr: int = 3, dst_addr: int = 1):
        self.host     = host
        self.port     = port
        self.timeout  = timeout
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.sock     = None
    
    def _crc16(self, data: bytes) -> int:
        """DNP3 CRC-16 calculation."""
        crc = 0
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
        return crc ^ 0xFFFF
    
    def _build_frame(self, func_code: int, data: bytes = b'') -> bytes:
        """Build DNP3 data link + application layer frame."""
        # Application layer PDU
        al_header = bytes([0xC0, func_code])
        al_pdu = al_header + data
        
        # Transport layer
        tl = bytes([0xC0]) + al_pdu
        
        # Data link layer
        payload = tl
        dl_length = 5 + len(payload)
        dl_header = struct.pack('<BBHH',
                                0x05, 0x64,        # Start bytes
                                dl_length,         # Length
                                0x44,              # Control (primary, FIR, FIN, UNR)
                                self.dst_addr) + struct.pack('<H', self.src_addr)
        
        header_crc = self._crc16(dl_header)
        frame = dl_header + struct.pack('<H', header_crc)
        
        # Add payload in blocks of 16 bytes with CRC
        for i in range(0, len(payload), 16):
            block = payload[i:i+16]
            block_crc = self._crc16(block)
            frame += block + struct.pack('<H', block_crc)
        
        return frame
    
    def probe(self) -> Optional[Dict]:
        """Send DNP3 link status request and parse response."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            
            # Link Status request
            frame = self._build_frame(0x01, b'')  # Read function code
            s.send(frame)
            
            resp = s.recv(256)
            s.close()
            
            if resp and len(resp) >= 8 and resp[0] == 0x05 and resp[1] == 0x64:
                src_addr = struct.unpack('<H', resp[6:8])[0]
                return {
                    'accessible': True,
                    'remote_address': src_addr,
                    'response_length': len(resp),
                    'raw_hex': binascii.hexlify(resp[:32]).decode(),
                }
        except Exception as e:
            return {'accessible': False, 'error': str(e)}
        return None
    
    def check_authentication(self) -> bool:
        """Check if DNP3 SAv5 authentication is enabled."""
        # Attempt unauthenticated read - if succeeds, auth is disabled
        result = self.probe()
        if result and result.get('accessible'):
            # No challenge received = no auth
            return False
        return True
    
    def full_assessment(self) -> ProtocolResult:
        result = ProtocolResult(protocol='DNP3', target=self.host, port=self.port,
                                success=False, data={})
        
        probe = self.probe()
        if not probe:
            result.error = "No response"
            return result
        
        result.success = True
        result.data = probe
        
        auth = self.check_authentication()
        result.data['authentication_enabled'] = auth
        if not auth:
            status(f"DNP3: No SAv5 authentication on {self.host}:{self.port}", 'VULN')
        
        return result


class IEC104Analyzer:
    """IEC 60870-5-104 protocol analyzer."""
    
    IEC104_PORT = 2404
    
    # APCI types
    I_FRAME  = 0x00  # Information
    S_FRAME  = 0x01  # Supervisory
    U_FRAME  = 0x03  # Unnumbered
    
    # Type Identification (TI)
    TYPE_IDS = {
        1:  'Single Point Information',
        3:  'Double Point Information',
        7:  'Step Position Information',
        9:  'Measured Value, Normalised',
        11: 'Measured Value, Scaled',
        13: 'Measured Value, Short Float',
        30: 'Single Point with Time Tag CP56Time2a',
        31: 'Double Point with Time Tag CP56Time2a',
        45: 'Single Command',
        46: 'Double Command',
        47: 'Regulating Step Command',
        48: 'Set Point Command, Normalised',
        100:'Interrogation Command',
        101:'Counter Interrogation Command',
        102:'Read Command',
        103:'Clock Synchronisation Command',
        104:'Test Command',
        105:'Reset Process Command',
    }
    
    def __init__(self, host: str, port: int = 2404, timeout: float = 5.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.sock    = None
        self.send_seq = 0
        self.recv_seq = 0
    
    def _build_apci(self, apdu: bytes) -> bytes:
        """Build IEC 104 APCI header."""
        return bytes([0x68, len(apdu)]) + apdu
    
    def _u_frame(self, func: int) -> bytes:
        """Build U-frame (STARTDT, STOPDT, TESTFR)."""
        return bytes([0x68, 0x04, func, 0x00, 0x00, 0x00])
    
    def connect_and_start(self) -> bool:
        """Connect and send STARTDT ACT."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            
            # Send STARTDT ACT
            self.sock.send(self._u_frame(0x07))  # STARTDT ACT
            resp = self.sock.recv(6)
            
            if len(resp) >= 6 and resp[0] == 0x68 and resp[2] == 0x0B:
                # STARTDT CON received
                return True
            elif len(resp) >= 4:
                return True  # Some response = connected
        except Exception:
            pass
        return False
    
    def general_interrogation(self) -> Optional[bytes]:
        """Send General Interrogation (Type 100) command."""
        if not self.sock:
            return None
        try:
            # ASDU: TI=100, VSQ=1, COT=6 (Act), CA=1, IOA=0, QOI=20 (Station)
            asdu = bytes([0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14])
            # I-Frame
            send_seq = (self.send_seq << 1) & 0xFFFF
            recv_seq = (self.recv_seq << 1) & 0xFFFF
            apdu = struct.pack('<HH', send_seq, recv_seq) + asdu
            packet = self._build_apci(apdu)
            self.sock.send(packet)
            self.send_seq += 1
            
            resp = self.sock.recv(1024)
            return resp
        except Exception:
            return None
    
    def full_assessment(self) -> ProtocolResult:
        result = ProtocolResult(protocol='IEC 60870-5-104', target=self.host,
                                port=self.port, success=False, data={})
        
        if not self.connect_and_start():
            result.error = "Connection or STARTDT failed"
            return result
        
        result.success = True
        result.data['startdt'] = 'ACK received'
        
        # General interrogation
        status(f"IEC104: General Interrogation to {self.host}:{self.port}", 'SCAN')
        gi_resp = self.general_interrogation()
        if gi_resp:
            result.data['gi_response'] = binascii.hexlify(gi_resp[:64]).decode()
            result.data['gi_bytes'] = len(gi_resp)
            status(f"IEC104: GI response received ({len(gi_resp)} bytes)", 'SUCCESS')
            # No authentication = CRITICAL
            status(f"IEC104: Accessible without authentication!", 'VULN')
            result.data['authentication'] = False
        
        if self.sock:
            self.sock.close()
        
        return result


class OPCUAAnalyzer:
    """OPC UA protocol analyzer."""
    
    OPCUA_PORT = 4840
    
    def __init__(self, host: str, port: int = 4840, timeout: float = 5.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
    
    def hello_message(self) -> Optional[bytes]:
        """Send OPC UA Hello message and get Acknowledge."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            
            endpoint = f"opc.tcp://{self.host}:{self.port}".encode()
            ep_len = len(endpoint)
            
            # OPC UA Hello Message
            # MessageType(3) + IsFinal(1) + MessageSize(4) + ProtocolVersion(4) +
            # ReceiveBufferSize(4) + SendBufferSize(4) + MaxMessageSize(4) +
            # MaxChunkCount(4) + EndpointUrlLength(4) + EndpointUrl(N)
            payload = struct.pack('<IIIIIII', 0, 65536, 65536, 0, 0, ep_len, 0)
            # Fix: proper structure
            hello_body = struct.pack('<II', 0, 65536)  # version, receiveBufferSize
            hello_body += struct.pack('<II', 65536, 0)  # sendBufferSize, maxMessageSize
            hello_body += struct.pack('<II', 0, ep_len)  # maxChunkCount, endpointUrlLen
            hello_body += endpoint
            
            msg_size = 8 + len(hello_body)
            header = b'HEL' + b'F' + struct.pack('<I', msg_size)
            
            s.send(header + hello_body)
            resp = s.recv(1024)
            s.close()
            
            if resp and resp[:3] == b'ACK':
                return resp
            return resp
        except Exception:
            return None
    
    def get_endpoints(self) -> List[Dict]:
        """Request endpoint list (reveals security modes)."""
        endpoints = []
        try:
            # This would require full OPC UA stack; simplified probe
            result = self.hello_message()
            if result:
                endpoints.append({
                    'accessible': True,
                    'response': binascii.hexlify(result[:32]).decode()
                })
        except Exception as e:
            pass
        return endpoints
    
    def full_assessment(self) -> ProtocolResult:
        result = ProtocolResult(protocol='OPC UA', target=self.host,
                                port=self.port, success=False, data={})
        
        status(f"OPC UA: Connecting to {self.host}:{self.port}", 'SCAN')
        resp = self.hello_message()
        
        if resp:
            result.success = True
            result.data['hello_ack'] = resp[:3] == b'ACK'
            result.data['response_hex'] = binascii.hexlify(resp[:32]).decode()
            result.data['response_length'] = len(resp)
            status(f"OPC UA: Server responded ({len(resp)} bytes)", 'SUCCESS')
            
            # If no security challenge, it may be NoSecurity mode
            if b'ACK' in resp:
                result.data['security_mode'] = 'Possibly None/Unencrypted'
                status(f"OPC UA: Server accessible, check security policies!", 'WARNING')
        else:
            result.error = "No response to Hello message"
        
        return result


class EtherNetIPAnalyzer:
    """EtherNet/IP (CIP) protocol analyzer."""
    
    ENIP_PORT    = 44818
    ENIP_UDP     = 2222
    
    # EtherNet/IP Commands
    CMD_LIST_IDENTITY   = 0x0063
    CMD_LIST_INTERFACES = 0x0064
    CMD_LIST_SERVICES   = 0x0004
    CMD_REGISTER_SESSION = 0x0065
    CMD_UNREGISTER_SESSION = 0x0066
    CMD_SEND_RR_DATA    = 0x0065
    
    def __init__(self, host: str, port: int = 44818, timeout: float = 3.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.session = 0
    
    def _build_enip(self, cmd: int, data: bytes = b'', session: int = 0) -> bytes:
        """Build EtherNet/IP encapsulation header."""
        # Command(2) + Length(2) + SessionHandle(4) + Status(4) +
        # SenderContext(8) + Options(4) + Data
        header = struct.pack('<HHII', cmd, len(data), session, 0)
        header += bytes([0x00] * 8)  # Sender context
        header += struct.pack('<I', 0)  # Options
        return header + data
    
    def list_identity(self) -> Optional[Dict]:
        """Send List Identity request - reveals device info."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            
            packet = self._build_enip(self.CMD_LIST_IDENTITY)
            s.send(packet)
            resp = s.recv(1024)
            s.close()
            
            if resp and len(resp) >= 26:
                # Parse List Identity response
                cmd = struct.unpack('<H', resp[0:2])[0]
                length = struct.unpack('<H', resp[2:4])[0]
                status_code = struct.unpack('<I', resp[8:12])[0]
                
                info = {
                    'command': hex(cmd),
                    'length': length,
                    'status': status_code,
                }
                
                # Parse CPF items if present
                if len(resp) >= 28:
                    item_count = struct.unpack('<H', resp[24:26])[0]
                    info['item_count'] = item_count
                    
                    # Try to extract identity data
                    if len(resp) > 42:
                        try:
                            # Vendor ID
                            vendor_id = struct.unpack('<H', resp[36:38])[0]
                            device_type = struct.unpack('<H', resp[38:40])[0]
                            product_code = struct.unpack('<H', resp[40:42])[0]
                            info['vendor_id'] = vendor_id
                            info['device_type'] = device_type
                            info['product_code'] = product_code
                        except Exception:
                            pass
                    
                    # Extract product name string
                    if len(resp) > 52:
                        name_len = resp[51] if len(resp) > 51 else 0
                        if name_len and len(resp) > 52 + name_len:
                            name = resp[52:52+name_len].decode('utf-8', errors='replace')
                            info['product_name'] = name
                
                return info
        except Exception as e:
            return {'error': str(e)}
        return None
    
    def list_identity_udp(self) -> Optional[Dict]:
        """UDP broadcast List Identity (discovers EIP devices on LAN)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            packet = self._build_enip(self.CMD_LIST_IDENTITY)
            s.sendto(packet, (self.host, self.ENIP_UDP))
            
            try:
                resp, addr = s.recvfrom(1024)
                return {'source': addr[0], 'response_len': len(resp),
                        'raw': binascii.hexlify(resp[:32]).decode()}
            except socket.timeout:
                pass
            s.close()
        except Exception:
            pass
        return None
    
    def full_assessment(self) -> ProtocolResult:
        result = ProtocolResult(protocol='EtherNet/IP', target=self.host,
                                port=self.port, success=False, data={})
        
        status(f"EtherNet/IP: List Identity from {self.host}:{self.port}", 'SCAN')
        identity = self.list_identity()
        
        if identity and 'error' not in identity:
            result.success = True
            result.data = identity
            
            if 'product_name' in identity:
                status(f"EtherNet/IP Device: {identity['product_name']}", 'SUCCESS')
            if 'vendor_id' in identity:
                status(f"Vendor ID: {identity['vendor_id']}, "
                       f"Device Type: {identity.get('device_type', 'N/A')}", 'DATA')
        elif identity:
            result.error = identity.get('error', 'Unknown')
        else:
            result.error = "No response"
        
        return result


class S7Analyzer:
    """Siemens S7 protocol analyzer."""
    
    S7_PORT = 102  # Uses TPKT/COTP
    
    def __init__(self, host: str, port: int = 102, timeout: float = 3.0,
                 rack: int = 0, slot: int = 1):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.rack    = rack
        self.slot    = slot
    
    def _cotp_connect(self, sock) -> bool:
        """Send COTP Connection Request (CR) TPDU."""
        # TPKT header: version(1) + reserved(1) + length(2)
        # COTP CR: length(1) + code(1) + dst-ref(2) + src-ref(2) + class(1) +
        #          param-code(1) + param-length(1) + tsap-data
        
        # Destination TSAP: 0x0100 + (rack*0x20 + slot) for S7 PLC
        dst_tsap = bytes([0x01, 0x00])
        src_tsap = bytes([0x01, 0x00])
        
        cotp = bytes([
            0x11,       # Length (17 bytes)
            0xE0,       # CR code
            0x00, 0x00, # Dst reference
            0x00, 0x01, # Src reference
            0x00,       # Class/Options
            0xC1, 0x02  # Param: SRC-TSAP
        ]) + src_tsap + bytes([
            0xC2, 0x02  # Param: DST-TSAP
        ]) + dst_tsap + bytes([
            0xC0, 0x01, 0x0A  # Param: TPDU-size = 1024
        ])
        
        tpkt = struct.pack('>BBH', 0x03, 0x00, 4 + len(cotp)) + cotp
        
        try:
            sock.send(tpkt)
            resp = sock.recv(256)
            # CC (Connection Confirm) = 0xD0
            if len(resp) >= 6 and resp[5] == 0xD0:
                return True
        except Exception:
            pass
        return False
    
    def _s7_setup(self, sock) -> bool:
        """Send S7 Setup Communication request."""
        # S7 request PDU
        s7_header = bytes([
            0x32, 0x01, # Protocol ID, ROSCTR (Job)
            0x00, 0x00, # Reserved
            0x00, 0x01, # PDU reference
            0x00, 0x08, # Parameter length
            0x00, 0x00, # Data length
        ])
        s7_param = bytes([
            0xF0, 0x00, # Function: Setup Comm
            0x00, 0x08, # Reserved + Max AmQ (calling)
            0x00, 0x08, # Max AmQ (called)
            0x03, 0xC0, # PDU length: 960
        ])
        
        s7_pdu = s7_header + s7_param
        cotp_dt = bytes([0x02, 0xF0, 0x80])  # DT data TPDU
        tpkt = struct.pack('>BBH', 0x03, 0x00, 4 + len(cotp_dt) + len(s7_pdu))
        
        packet = tpkt + cotp_dt + s7_pdu
        
        try:
            sock.send(packet)
            resp = sock.recv(256)
            # Check for S7 ACK
            if len(resp) > 10 and resp[7] == 0x32 and resp[8] == 0x03:
                return True
        except Exception:
            pass
        return False
    
    def read_szl(self, sock, szl_id: int = 0x0011, szl_idx: int = 0x0000) -> Optional[bytes]:
        """Read SZL (System Status List) - reveals CPU/firmware info."""
        # S7 SZL read request
        s7_header = bytes([0x32, 0x07, 0x00, 0x00, 0x05, 0x01, 0x00, 0x08, 0x00, 0x08])
        s7_param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
        s7_data = bytes([0x00, 0x04, 0x00, 0x00]) + struct.pack('>HH', szl_id, szl_idx)
        
        s7_pdu = s7_header + s7_param + s7_data
        cotp_dt = bytes([0x02, 0xF0, 0x80])
        tpkt = struct.pack('>BBH', 0x03, 0x00, 4 + len(cotp_dt) + len(s7_pdu))
        
        try:
            sock.send(tpkt + cotp_dt + s7_pdu)
            resp = sock.recv(1024)
            return resp
        except Exception:
            return None
    
    def full_assessment(self) -> ProtocolResult:
        result = ProtocolResult(protocol='S7/TPKT', target=self.host,
                                port=self.port, success=False, data={})
        
        status(f"S7: Connecting to {self.host}:{self.port} (rack={self.rack}, slot={self.slot})", 'SCAN')
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            if self._cotp_connect(sock):
                result.data['cotp_connect'] = True
                status(f"S7: COTP connection established", 'SUCCESS')
                
                if self._s7_setup(sock):
                    result.success = True
                    result.data['s7_setup'] = True
                    status(f"S7: Communication setup complete", 'SUCCESS')
                    
                    # Read CPU information via SZL 0x0011
                    szl_data = self.read_szl(sock, 0x0011, 0x0001)
                    if szl_data:
                        result.data['szl_response_hex'] = binascii.hexlify(szl_data[:64]).decode()
                        # Extract CPU order number (starts at offset ~28 in SZL response)
                        try:
                            order_num = szl_data[30:50].decode('utf-8', errors='replace').strip('\x00')
                            result.data['cpu_order_number'] = order_num
                            status(f"S7: CPU Order: {order_num}", 'DATA')
                        except Exception:
                            pass
                    
                    # CRITICAL: No auth required
                    status(f"S7: PLC accessible without password!", 'VULN')
                    result.data['authentication'] = 'None required'
                else:
                    result.data['s7_setup'] = False
            else:
                result.error = "COTP connection refused (wrong rack/slot?)"
            
            sock.close()
        except ConnectionRefusedError:
            result.error = "Connection refused"
        except socket.timeout:
            result.error = "Connection timeout"
        except Exception as e:
            result.error = str(e)
        
        return result


class MQTTAnalyzer:
    """MQTT protocol analyzer for IIoT devices."""
    
    MQTT_PORT = 1883
    
    def __init__(self, host: str, port: int = 1883, timeout: float = 3.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
    
    def _build_connect(self, client_id: str = "ot_scanner", 
                       username: str = "", password: str = "") -> bytes:
        """Build MQTT CONNECT packet."""
        protocol_name = b'MQTT'
        protocol_level = 4  # MQTT 3.1.1
        
        connect_flags = 0x02  # Clean session
        if username:
            connect_flags |= 0x80
        if password:
            connect_flags |= 0x40
        
        keep_alive = 60
        
        # Payload
        client_id_bytes = client_id.encode()
        payload = struct.pack('>H', len(client_id_bytes)) + client_id_bytes
        if username:
            u = username.encode()
            payload += struct.pack('>H', len(u)) + u
        if password:
            p = password.encode()
            payload += struct.pack('>H', len(p)) + p
        
        # Variable header
        var_header = struct.pack('>H', len(protocol_name)) + protocol_name
        var_header += bytes([protocol_level, connect_flags])
        var_header += struct.pack('>H', keep_alive)
        
        remaining = var_header + payload
        
        # Fixed header
        remaining_len = len(remaining)
        enc_len = []
        while True:
            enc_byte = remaining_len % 128
            remaining_len //= 128
            if remaining_len > 0:
                enc_byte |= 0x80
            enc_len.append(enc_byte)
            if remaining_len == 0:
                break
        
        return bytes([0x10] + enc_len) + remaining
    
    def connect_and_probe(self, username: str = "", password: str = "") -> Dict:
        """Attempt MQTT connection."""
        result = {'connected': False}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            
            connect_pkt = self._build_connect("ot_sec_scanner", username, password)
            s.send(connect_pkt)
            
            resp = s.recv(4)
            if len(resp) >= 4 and resp[0] == 0x20:  # CONNACK
                return_code = resp[3]
                result['connected']   = return_code == 0
                result['return_code'] = return_code
                rc_meanings = {
                    0: 'Connection Accepted',
                    1: 'Unacceptable Protocol Version',
                    2: 'Identifier Rejected',
                    3: 'Server Unavailable',
                    4: 'Bad User Name or Password',
                    5: 'Not Authorized',
                }
                result['meaning'] = rc_meanings.get(return_code, f'Unknown ({return_code})')
            
            s.close()
        except Exception as e:
            result['error'] = str(e)
        return result
    
    def check_anonymous_access(self) -> bool:
        """Check if MQTT broker allows anonymous connections."""
        result = self.connect_and_probe()
        return result.get('connected', False)
    
    def try_default_credentials(self) -> Optional[Tuple[str, str]]:
        """Test common MQTT default credentials."""
        defaults = [
            ('', ''), ('admin', 'admin'), ('admin', ''),
            ('user', 'user'), ('mqtt', 'mqtt'), ('test', 'test'),
            ('guest', 'guest'), ('admin', 'password'),
            ('root', 'root'), ('admin', '123456'),
        ]
        for user, pwd in defaults:
            r = self.connect_and_probe(user, pwd)
            if r.get('connected'):
                return (user, pwd)
        return None
    
    def full_assessment(self) -> ProtocolResult:
        result = ProtocolResult(protocol='MQTT', target=self.host,
                                port=self.port, success=False, data={})
        
        status(f"MQTT: Testing {self.host}:{self.port}", 'SCAN')
        
        anon = self.check_anonymous_access()
        result.data['anonymous_access'] = anon
        
        if anon:
            result.success = True
            status(f"MQTT: Anonymous access allowed on {self.host}:{self.port}!", 'VULN')
        else:
            status("MQTT: Anonymous access denied. Testing credentials...", 'INFO')
            creds = self.try_default_credentials()
            if creds:
                result.success = True
                result.data['default_credentials'] = {'username': creds[0], 'password': creds[1]}
                status(f"MQTT: Default credentials work: {creds[0]}:{creds[1]}", 'VULN')
            else:
                result.data['authentication'] = 'Enabled'
                status(f"MQTT: Authentication is enforced", 'SUCCESS')
        
        return result


class BACnetAnalyzer:
    """BACnet/IP protocol analyzer."""
    
    BACNET_PORT = 47808
    
    def __init__(self, host: str, port: int = 47808, timeout: float = 3.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout
    
    def who_is(self) -> Optional[bytes]:
        """Send BACnet WhoIs broadcast."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # BACnet/IP BVLC + NPDU + APDU (WhoIs)
            bvlc  = bytes([0x81, 0x0b, 0x00, 0x0c])  # BVLC Original-Broadcast-NPDU
            npdu  = bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])  # NPDU broadcast
            apdu  = bytes([0x10, 0x08])  # Unconfirmed WhoIs
            
            packet = bvlc + npdu + apdu
            s.sendto(packet, (self.host, self.port))
            
            try:
                resp, addr = s.recvfrom(1024)
                return resp
            except socket.timeout:
                pass
            s.close()
        except Exception:
            pass
        return None
    
    def read_property(self, device_id: int = 1, object_type: int = 8,
                      object_instance: int = 1, property_id: int = 77) -> Optional[bytes]:
        """BACnet ReadProperty request."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            
            # ReadProperty PDU
            bvlc = bytes([0x81, 0x0a, 0x00, 0x11])  # Original-Unicast-NPDU
            npdu = bytes([0x01, 0x04])
            # APDU: Confirmed ReadProperty
            apdu = bytes([
                0x00, 0x05,         # PDU type + Invoke ID
                0x0C,               # Service: ReadProperty
                0x0C,               # Context tag 0, length 4
            ])
            apdu += struct.pack('>I', (object_type << 22) | object_instance)
            apdu += bytes([0x19, property_id])  # Context tag 1: PropertyIdentifier
            
            packet = bvlc + npdu + apdu
            s.sendto(packet, (self.host, self.port))
            
            try:
                resp, _ = s.recvfrom(1024)
                return resp
            except socket.timeout:
                pass
            s.close()
        except Exception:
            pass
        return None
    
    def full_assessment(self) -> ProtocolResult:
        result = ProtocolResult(protocol='BACnet/IP', target=self.host,
                                port=self.port, success=False, data={})
        
        status(f"BACnet: WhoIs broadcast to {self.host}:{self.port}", 'SCAN')
        resp = self.who_is()
        
        if resp:
            result.success = True
            result.data['whois_response'] = binascii.hexlify(resp[:32]).decode()
            result.data['response_length'] = len(resp)
            status(f"BACnet: Device responded to WhoIs ({len(resp)} bytes)", 'SUCCESS')
            status(f"BACnet: Device accessible without authentication!", 'WARNING')
        else:
            result.error = "No WhoIs response"
        
        return result


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 3: PLC SECURITY ASSESSMENT
# ─────────────────────────────────────────────────────────────────────────────

class PLCSecurityAssessor:
    """Comprehensive PLC security assessment module."""
    
    # Common PLC default credentials
    DEFAULT_CREDS = [
        ('', ''),
        ('admin', 'admin'), ('admin', ''), ('admin', 'password'),
        ('administrator', 'administrator'), ('administrator', ''),
        ('user', 'user'), ('user', ''), ('guest', 'guest'),
        ('root', 'root'), ('root', ''),
        ('siemens', 'siemens'), ('siemens', '100'),
        ('plc', 'plc'), ('service', 'service'),
        ('engineer', 'engineer'), ('technician', ''),
        ('admin', '1234'), ('admin', '12345'), ('admin', '123456'),
        ('admin', '0000'), ('admin', '9999'),
    ]
    
    def __init__(self, logger: FrameworkLogger, timeout: float = 3.0):
        self.logger  = logger
        self.timeout = timeout
        self.vulns:  List[Vulnerability] = []
    
    def _add_vuln(self, vuln_id: str, title: str, severity: Severity,
                  device_ip: str, description: str, protocol: str = "",
                  remediation: str = "", cvss: float = 0.0, cve: str = "",
                  evidence: str = ""):
        v = Vulnerability(
            vuln_id=vuln_id, title=title, severity=severity,
            device_ip=device_ip, description=description,
            protocol=protocol, remediation=remediation,
            cvss=cvss, cve=cve, evidence=evidence
        )
        self.vulns.append(v)
        self.logger.vuln(f"[{severity.name}] {title} on {device_ip}")
        return v
    
    def assess_modbus(self, ip: str, port: int = 502) -> List[Vulnerability]:
        """Modbus-specific security assessment."""
        vulns = []
        analyzer = ModbusTCPAnalyzer(ip, port, self.timeout)
        
        if not analyzer.connect():
            return vulns
        
        status(f"Modbus assessment on {ip}:{port}", 'SCAN')
        
        # Check 1: Unauthenticated access
        regs = analyzer.read_holding_registers(0, 10)
        if regs is not None:
            v = self._add_vuln(
                'MODBUS-001', 'Modbus TCP Unauthenticated Access',
                Severity.CRITICAL, ip,
                'Modbus TCP device accessible without authentication. '
                'Any network attacker can read/write PLC registers.',
                protocol='Modbus TCP',
                remediation='Deploy VPN or protocol gateway with authentication. '
                            'Implement network segmentation. Use Modbus/TCP with SSL.',
                cvss=9.8, evidence=f"Registers read: {regs[:5]}"
            )
            vulns.append(v)
        
        # Check 2: Write access
        write_access = analyzer.check_write_access()
        if write_access.get('write_registers'):
            v = self._add_vuln(
                'MODBUS-002', 'Unauthorized Modbus Write Access',
                Severity.CRITICAL, ip,
                'Modbus TCP device allows unauthenticated write operations. '
                'Attacker can modify PLC register values and control outputs.',
                protocol='Modbus TCP',
                remediation='Configure Modbus device to reject write commands from '
                            'unauthorized sources. Use allowlisting by IP address.',
                cvss=10.0, evidence="Write coil/register accepted without authentication"
            )
            vulns.append(v)
        
        # Check 3: No source address filtering
        # (We're connecting from an external IP without restriction)
        v = self._add_vuln(
            'MODBUS-003', 'No Source Address Filtering',
            Severity.HIGH, ip,
            'Modbus device accepts connections from arbitrary source IPs.',
            protocol='Modbus TCP',
            remediation='Configure firewall rules to allow Modbus only from authorized sources.',
            cvss=7.5
        )
        vulns.append(v)
        
        analyzer.disconnect()
        return vulns
    
    def assess_s7(self, ip: str, port: int = 102,
                  rack: int = 0, slot: int = 1) -> List[Vulnerability]:
        """Siemens S7 PLC security assessment."""
        vulns = []
        analyzer = S7Analyzer(ip, port, self.timeout, rack, slot)
        result = analyzer.full_assessment()
        
        if result.success:
            if result.data.get('s7_setup'):
                v = self._add_vuln(
                    'S7-001', 'S7 PLC Accessible Without Password',
                    Severity.CRITICAL, ip,
                    'Siemens S7 PLC accessible without access level password. '
                    'Full read/write access to CPU memory and I/O.',
                    protocol='S7/TPKT',
                    remediation='Enable protection level 1-3 in STEP 7/TIA Portal. '
                                'Set passwords for know-how protection and copy protection.',
                    cvss=9.8,
                    evidence=f"S7 setup complete, CPU: {result.data.get('cpu_order_number', 'N/A')}"
                )
                vulns.append(v)
            
            if result.data.get('cpu_order_number'):
                v = self._add_vuln(
                    'S7-002', 'S7 CPU Order Number Disclosed',
                    Severity.MEDIUM, ip,
                    f"CPU order number disclosed: {result.data['cpu_order_number']}. "
                    "Enables targeted firmware exploit research.",
                    protocol='S7/TPKT',
                    remediation='Restrict S7 protocol access. Use Siemens Security Shield.',
                    cvss=5.3,
                    evidence=result.data['cpu_order_number']
                )
                vulns.append(v)
        
        return vulns
    
    def check_web_interface(self, ip: str, ports: List[int] = None) -> List[Vulnerability]:
        """Check for web-based management interfaces."""
        if ports is None:
            ports = [80, 443, 8080, 8443, 8000, 8001, 9000]
        vulns = []
        
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((ip, port)) == 0:
                    # Grab HTTP response
                    s.send(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    try:
                        resp = s.recv(2048).decode('utf-8', errors='replace')
                        
                        proto = 'HTTPS' if port in [443, 8443] else 'HTTP'
                        
                        # Check for default page
                        if any(keyword in resp.lower() for keyword in
                               ['siemens', 'allen-bradley', 'schneider', 'modicon',
                                'rockwell', 'plc', 'hmi', 'scada', 'webserver']):
                            v = self._add_vuln(
                                f'WEB-001-{port}',
                                f'Industrial Web Interface Exposed ({proto}:{port})',
                                Severity.HIGH, ip,
                                f'Industrial device web interface accessible on port {port}. '
                                'Web management interfaces are common attack targets.',
                                protocol=proto,
                                remediation='Restrict web access via firewall. '
                                           'Enable HTTPS and authentication. '
                                           'Disable web interface if not required.',
                                cvss=7.3,
                                evidence=resp[:200]
                            )
                            vulns.append(v)
                        
                        # Check for telnet
                        if 'telnet' in resp.lower() or port == 23:
                            v = self._add_vuln(
                                'TELNET-001',
                                'Unencrypted Telnet Service Detected',
                                Severity.CRITICAL, ip,
                                'Telnet provides unencrypted remote access. '
                                'Credentials transmitted in cleartext.',
                                protocol='Telnet',
                                remediation='Disable Telnet. Use SSH instead.',
                                cvss=9.8
                            )
                            vulns.append(v)
                    except Exception:
                        pass
                s.close()
            except Exception:
                pass
        
        return vulns
    
    def check_snmp(self, ip: str) -> List[Vulnerability]:
        """SNMP security checks."""
        vulns = []
        
        # Common community strings
        communities = ['public', 'private', 'community', 'admin', 'manager',
                       'default', 'cisco', 'snmp', 'ILMI', '0']
        
        for community in communities:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(self.timeout)
                
                # SNMPv1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
                oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
                varbind = bytes([0x30, len(oid) + 4]) + oid + bytes([0x05, 0x00])
                varbindlist = bytes([0x30, len(varbind)]) + varbind
                
                comm = community.encode()
                pdu = bytes([0xa0, len(varbindlist) + 8, 0x02, 0x01, 0x01,
                             0x02, 0x01, 0x00, 0x02, 0x01, 0x00]) + varbindlist
                
                snmp_msg = (bytes([0x30]) +
                            bytes([2 + 2 + len(comm) + len(pdu)]) +
                            bytes([0x02, 0x01, 0x00]) +
                            bytes([0x04, len(comm)]) +
                            comm + pdu)
                
                s.sendto(snmp_msg, (ip, 161))
                try:
                    resp, _ = s.recvfrom(1024)
                    if resp and len(resp) > 10:
                        v = self._add_vuln(
                            f'SNMP-001-{community}',
                            f'SNMP Default Community String: "{community}"',
                            Severity.HIGH if community in ['public', 'private']
                            else Severity.CRITICAL,
                            ip,
                            f'SNMP community string "{community}" is active. '
                            'Allows device enumeration and potentially configuration changes.',
                            protocol='SNMP',
                            remediation='Change community strings to random complex values. '
                                       'Disable SNMPv1/v2c. Use SNMPv3 with auth+privacy.',
                            cvss=7.5,
                            evidence=f"Community '{community}' accepted"
                        )
                        vulns.append(v)
                        break
                except socket.timeout:
                    pass
                s.close()
            except Exception:
                pass
        
        return vulns
    
    def firmware_assessment(self, ip: str, device: IndustrialDevice) -> List[Vulnerability]:
        """PLC firmware and configuration assessment."""
        vulns = []
        
        # Check for FTP access (firmware download)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            if s.connect_ex((ip, 21)) == 0:
                banner = b""
                try:
                    banner = s.recv(1024)
                    # Try anonymous login
                    s.send(b"USER anonymous\r\n")
                    r1 = s.recv(256)
                    if b'331' in r1:
                        s.send(b"PASS scanner@test.com\r\n")
                        r2 = s.recv(256)
                        if b'230' in r2:
                            v = self._add_vuln(
                                'FTP-001', 'Anonymous FTP Access Allowed',
                                Severity.HIGH, ip,
                                'FTP server allows anonymous login. '
                                'May expose firmware, configuration files.',
                                protocol='FTP',
                                remediation='Disable FTP. Use SFTP/SCP. '
                                           'Disable anonymous access.',
                                cvss=7.5,
                                evidence=f"Banner: {banner.decode('utf-8', errors='replace')[:100]}"
                            )
                            vulns.append(v)
                except Exception:
                    pass
                s.close()
        except Exception:
            pass
        
        # Check firmware version disclosure
        for svc in device.services:
            if svc.banner:
                # Look for version strings
                ver_match = re.search(r'[Vv]ersion\s*([\d.]+)', svc.banner)
                fw_match = re.search(r'[Ff]irmware\s*([\d.]+)', svc.banner)
                if ver_match or fw_match:
                    ver = (ver_match or fw_match).group(1)
                    v = self._add_vuln(
                        'FW-001', f'Firmware Version Disclosed: {ver}',
                        Severity.LOW, ip,
                        f'Device discloses firmware version {ver} in service banner. '
                        'Enables targeted vulnerability research.',
                        protocol=svc.service,
                        remediation='Configure devices to suppress version information in banners.',
                        cvss=5.3,
                        evidence=svc.banner[:200]
                    )
                    vulns.append(v)
        
        return vulns
    
    def full_assessment(self, ip: str, device: IndustrialDevice) -> List[Vulnerability]:
        """Run full PLC security assessment."""
        print_section(f"PLC SECURITY ASSESSMENT: {ip}")
        all_vulns = []
        
        open_ports = {s.port for s in device.services}
        
        # Protocol-specific assessments
        if 502 in open_ports:
            status(f"Running Modbus TCP assessment", 'INFO')
            all_vulns.extend(self.assess_modbus(ip))
        
        if 102 in open_ports:
            status(f"Running S7/TPKT assessment", 'INFO')
            all_vulns.extend(self.assess_s7(ip))
        
        # Web interfaces
        status(f"Checking web management interfaces", 'INFO')
        all_vulns.extend(self.check_web_interface(ip))
        
        # SNMP
        if 161 in open_ports:
            status(f"Running SNMP assessment", 'INFO')
            all_vulns.extend(self.check_snmp(ip))
        
        # Firmware
        status(f"Running firmware assessment", 'INFO')
        all_vulns.extend(self.firmware_assessment(ip, device))
        
        # Protocol analyzers for other protocols
        proto_analyzers = {
            44818: ('EtherNet/IP', lambda: EtherNetIPAnalyzer(ip, 44818, self.timeout).full_assessment()),
            20000: ('DNP3',        lambda: DNP3Analyzer(ip, 20000, self.timeout).full_assessment()),
            2404:  ('IEC104',      lambda: IEC104Analyzer(ip, 2404, self.timeout).full_assessment()),
            4840:  ('OPC-UA',      lambda: OPCUAAnalyzer(ip, 4840, self.timeout).full_assessment()),
            1883:  ('MQTT',        lambda: MQTTAnalyzer(ip, 1883, self.timeout).full_assessment()),
            47808: ('BACnet',      lambda: BACnetAnalyzer(ip, 47808, self.timeout).full_assessment()),
        }
        
        for port, (proto_name, assess_fn) in proto_analyzers.items():
            if port in open_ports:
                status(f"Running {proto_name} assessment", 'INFO')
                try:
                    pr = assess_fn()
                    if pr.success and pr.data:
                        # Add info-level vuln for accessible service
                        if not pr.error:
                            all_vulns.append(Vulnerability(
                                vuln_id=f'{proto_name.replace("/","_").replace("-","_")}-ACC',
                                title=f'{proto_name} Service Accessible',
                                severity=Severity.HIGH,
                                device_ip=ip,
                                description=f'{proto_name} service accessible on port {port}.',
                                protocol=proto_name,
                                remediation='Restrict access via network segmentation and firewall rules.',
                                evidence=str(pr.data)[:300]
                            ))
                except Exception as e:
                    self.logger.error(f"{proto_name} assessment error: {e}")
        
        # Telnet check
        if 23 in open_ports:
            all_vulns.append(self._add_vuln(
                'TELNET-001', 'Telnet Service Enabled',
                Severity.CRITICAL, ip,
                'Telnet provides unencrypted access. Credentials sent in cleartext.',
                protocol='Telnet',
                remediation='Disable Telnet. Migrate to SSH.',
                cvss=9.8
            ))
        
        # Print assessment results
        self._print_vuln_summary(all_vulns, ip)
        
        return all_vulns
    
    def _print_vuln_summary(self, vulns: List[Vulnerability], ip: str):
        """Print formatted vulnerability summary."""
        if not vulns:
            status(f"No vulnerabilities found on {ip}", 'SUCCESS')
            return
        
        print(f"\n  {Colors.BORDER}{'═'*73}")
        print(f"  {Colors.HEADER}  VULNERABILITY REPORT: {ip}")
        print(f"  {Colors.BORDER}{'═'*73}{Colors.RESET}")
        
        # Count by severity
        sev_counts = defaultdict(int)
        for v in vulns:
            sev_counts[v.severity.name] += 1
        
        sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        for sev in sev_order:
            count = sev_counts.get(sev, 0)
            if count:
                color = Colors.SEVERITY.get(sev, Colors.NEUTRAL)
                bar = '█' * count + '░' * max(0, 10 - count)
                print(f"  {color}{sev:10s}{Colors.RESET} {Colors.BORDER}│{Colors.RESET} "
                      f"{color}{bar}{Colors.RESET} {count}")
        
        print(f"  {Colors.BORDER}{'─'*73}")
        
        # List vulns sorted by severity
        for v in sorted(vulns, key=lambda x: x.severity.value, reverse=True):
            color = Colors.SEVERITY.get(v.severity.name, Colors.NEUTRAL)
            print(f"\n  {color}[{v.severity.name}]{Colors.RESET} "
                  f"{Colors.DATA}{v.vuln_id}{Colors.RESET} - "
                  f"{Colors.WARNING}{v.title}{Colors.RESET}")
            print(f"  {Colors.BORDER}  Description:{Colors.RESET} "
                  f"{Colors.DATA_DIM}{v.description[:100]}{Colors.RESET}")
            if v.remediation:
                print(f"  {Colors.BORDER}  Fix:{Colors.RESET} "
                      f"{Colors.SUCCESS}{v.remediation[:100]}{Colors.RESET}")
            if v.cvss:
                cvss_color = (Colors.CRITICAL if v.cvss >= 9 else
                             Colors.ERROR if v.cvss >= 7 else
                             Colors.WARNING if v.cvss >= 4 else Colors.INFO)
                print(f"  {Colors.BORDER}  CVSS:{Colors.RESET} "
                      f"{cvss_color}{v.cvss:.1f}{Colors.RESET}")
        
        print(f"\n  {Colors.BORDER}{'═'*73}{Colors.RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# MODULE 4: REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Generate assessment reports in multiple formats."""
    
    def __init__(self, devices: Dict[str, IndustrialDevice],
                 vulnerabilities: List[Vulnerability],
                 scan_config: Dict):
        self.devices = devices
        self.vulns   = vulnerabilities
        self.config  = scan_config
        self.ts      = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def generate_json(self, output_file: str = None) -> str:
        """Generate JSON report."""
        if not output_file:
            output_file = f"ot_report_{self.ts}.json"
        
        report = {
            'metadata': {
                'tool':       'OT/ICS Industrial Penetration Testing Framework v2.0',
                'timestamp':  datetime.now().isoformat(),
                'scan_config': self.config,
            },
            'summary': {
                'total_devices':         len(self.devices),
                'total_vulnerabilities': len(self.vulns),
                'critical':  sum(1 for v in self.vulns if v.severity == Severity.CRITICAL),
                'high':      sum(1 for v in self.vulns if v.severity == Severity.HIGH),
                'medium':    sum(1 for v in self.vulns if v.severity == Severity.MEDIUM),
                'low':       sum(1 for v in self.vulns if v.severity == Severity.LOW),
            },
            'devices':         [d.to_dict() for d in self.devices.values()],
            'vulnerabilities': [v.to_dict() for v in self.vulns],
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        status(f"JSON report: {output_file}", 'SUCCESS')
        return output_file
    
    def generate_csv(self, output_file: str = None) -> str:
        """Generate CSV vulnerability report."""
        if not output_file:
            output_file = f"ot_vulns_{self.ts}.csv"
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'vuln_id', 'title', 'severity', 'device_ip', 'cvss',
                'cve', 'protocol', 'description', 'remediation', 'evidence', 'timestamp'
            ])
            writer.writeheader()
            for v in sorted(self.vulns, key=lambda x: x.severity.value, reverse=True):
                writer.writerow(v.to_dict())
        
        status(f"CSV report: {output_file}", 'SUCCESS')
        return output_file
    
    def generate_html(self, output_file: str = None) -> str:
        """Generate HTML report."""
        if not output_file:
            output_file = f"ot_report_{self.ts}.html"
        
        sev_counts = defaultdict(int)
        for v in self.vulns:
            sev_counts[v.severity.name] += 1
        
        sev_colors = {
            'CRITICAL': '#FF0000', 'HIGH': '#FF6600',
            'MEDIUM': '#FFAA00', 'LOW': '#FFFF00',
            'INFO': '#00AAFF', 'NONE': '#888888'
        }
        
        device_rows = ""
        for dev in self.devices.values():
            protos = ', '.join(dev.protocols[:5])
            ports  = ', '.join(str(s.port) for s in dev.services[:8])
            device_rows += f"""
            <tr>
                <td class="ip">{dev.ip}</td>
                <td>{dev.device_type.value}</td>
                <td>{dev.vendor or 'Unknown'}</td>
                <td>{protos or 'N/A'}</td>
                <td>{ports or 'None'}</td>
                <td>{dev.hostname or 'N/A'}</td>
            </tr>"""
        
        vuln_rows = ""
        for v in sorted(self.vulns, key=lambda x: x.severity.value, reverse=True):
            color = sev_colors.get(v.severity.name, '#888')
            vuln_rows += f"""
            <tr>
                <td><span class="sev-badge" style="background:{color}">{v.severity.name}</span></td>
                <td class="ip">{v.device_ip}</td>
                <td><strong>{v.vuln_id}</strong></td>
                <td>{v.title}</td>
                <td>{v.cvss:.1f}</td>
                <td>{v.protocol}</td>
                <td class="desc">{v.description[:150]}</td>
            </tr>"""
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OT/ICS Security Assessment Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0f1e; color: #c8d6e5; font-family: 'Consolas', 'Courier New', monospace; }}
  header {{ background: linear-gradient(135deg, #0d1b2a, #1a2f4a); padding: 40px;
           border-bottom: 2px solid #00d4ff; }}
  header h1 {{ color: #00d4ff; font-size: 28px; letter-spacing: 3px; }}
  header .subtitle {{ color: #7f8fa6; margin-top: 8px; font-size: 14px; }}
  .warning-banner {{ background: #2d0000; border: 1px solid #ff0000; color: #ff6666;
                    padding: 15px 40px; font-size: 13px; text-align: center; }}
  .container {{ padding: 30px 40px; }}
  h2 {{ color: #00d4ff; font-size: 18px; margin: 30px 0 15px;
        padding-bottom: 8px; border-bottom: 1px solid #1a2f4a; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                  gap: 15px; margin: 20px 0; }}
  .metric {{ background: #0d1b2a; border: 1px solid #1a2f4a; border-radius: 8px;
            padding: 20px; text-align: center; }}
  .metric .val {{ font-size: 36px; font-weight: bold; }}
  .metric .lab {{ font-size: 12px; color: #7f8fa6; margin-top: 5px; letter-spacing: 1px; }}
  .metric.critical .val {{ color: #ff0000; }}
  .metric.high .val {{ color: #ff6600; }}
  .metric.medium .val {{ color: #ffaa00; }}
  .metric.low .val {{ color: #00ff88; }}
  .metric.info .val {{ color: #00d4ff; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin: 15px 0; }}
  th {{ background: #0d1b2a; color: #00d4ff; padding: 12px 15px; text-align: left;
        border-bottom: 2px solid #1a2f4a; letter-spacing: 1px; font-size: 11px; }}
  td {{ padding: 10px 15px; border-bottom: 1px solid #0d1b2a; }}
  tr:hover {{ background: #0d1b2a; }}
  .ip {{ color: #ff79c6; font-weight: bold; }}
  .sev-badge {{ padding: 3px 8px; border-radius: 3px; font-size: 10px;
               font-weight: bold; color: #000; }}
  .desc {{ color: #7f8fa6; font-size: 12px; }}
  footer {{ text-align: center; padding: 30px; color: #3d4f62; font-size: 12px;
           border-top: 1px solid #1a2f4a; }}
</style>
</head>
<body>
<header>
  <h1>⚡ OT/ICS INDUSTRIAL SECURITY ASSESSMENT REPORT</h1>
  <div class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Target: {self.config.get('network', 'N/A')}</div>
</header>
<div class="warning-banner">
  ⚠ CONFIDENTIAL — FOR AUTHORIZED SECURITY TESTING ONLY — DO NOT DISTRIBUTE ⚠
</div>
<div class="container">
  <h2>EXECUTIVE SUMMARY</h2>
  <div class="summary-grid">
    <div class="metric"><div class="val" style="color:#00d4ff">{len(self.devices)}</div><div class="lab">DEVICES</div></div>
    <div class="metric"><div class="val" style="color:#00d4ff">{len(self.vulns)}</div><div class="lab">FINDINGS</div></div>
    <div class="metric critical"><div class="val">{sev_counts['CRITICAL']}</div><div class="lab">CRITICAL</div></div>
    <div class="metric high"><div class="val">{sev_counts['HIGH']}</div><div class="lab">HIGH</div></div>
    <div class="metric medium"><div class="val">{sev_counts['MEDIUM']}</div><div class="lab">MEDIUM</div></div>
    <div class="metric low"><div class="val">{sev_counts['LOW']}</div><div class="lab">LOW</div></div>
  </div>

  <h2>DISCOVERED ASSETS</h2>
  <table>
    <thead><tr>
      <th>IP ADDRESS</th><th>DEVICE TYPE</th><th>VENDOR</th>
      <th>PROTOCOLS</th><th>OPEN PORTS</th><th>HOSTNAME</th>
    </tr></thead>
    <tbody>{device_rows}</tbody>
  </table>

  <h2>VULNERABILITY FINDINGS</h2>
  <table>
    <thead><tr>
      <th>SEVERITY</th><th>HOST</th><th>ID</th><th>TITLE</th>
      <th>CVSS</th><th>PROTOCOL</th><th>DESCRIPTION</th>
    </tr></thead>
    <tbody>{vuln_rows}</tbody>
  </table>
</div>
<footer>OT/ICS Industrial Penetration Testing Framework v2.0 | For Authorized Use Only</footer>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        status(f"HTML report: {output_file}", 'SUCCESS')
        return output_file
    
    def generate_all(self) -> Dict[str, str]:
        """Generate all report formats."""
        print_section("GENERATING REPORTS")
        return {
            'json': self.generate_json(),
            'csv':  self.generate_csv(),
            'html': self.generate_html(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN FRAMEWORK CONTROLLER
# ─────────────────────────────────────────────────────────────────────────────

class OTFramework:
    """Main OT/ICS Penetration Testing Framework controller."""
    
    def __init__(self, args: argparse.Namespace):
        self.args    = args
        self.logger  = FrameworkLogger(
            log_file=args.log_file if hasattr(args, 'log_file') else 'ot_framework.log',
            verbose=args.verbose if hasattr(args, 'verbose') else False
        )
        self.devices:  Dict[str, IndustrialDevice] = {}
        self.vulns:    List[Vulnerability]         = []
        self.start_ts  = datetime.now()
        
        # Modules
        self.discovery  = AssetDiscovery(
            self.logger,
            timeout=getattr(args, 'timeout', 2.0),
            threads=getattr(args, 'threads', 50)
        )
        self.assessor   = PLCSecurityAssessor(
            self.logger,
            timeout=getattr(args, 'timeout', 3.0)
        )
    
    def run_discovery(self):
        """Run full asset discovery."""
        network = getattr(self.args, 'network', '192.168.1.0/24')
        iface   = getattr(self.args, 'interface', None)
        full    = getattr(self.args, 'full_scan', False)
        
        self.devices = self.discovery.discover_network(network, iface, full)
        
        if self.devices:
            self.discovery.topology_map()
            self._print_discovery_summary()
    
    def run_passive(self):
        """Run passive asset inventory."""
        iface    = getattr(self.args, 'interface', 'eth0')
        duration = getattr(self.args, 'duration', 60)
        
        self.devices = self.discovery.passive_inventory(iface, duration)
    
    def run_protocol_analysis(self):
        """Run protocol-specific analysis on all discovered devices."""
        print_section("INDUSTRIAL PROTOCOL ANALYSIS")
        
        if not self.devices:
            status("No devices to analyze. Run discovery first.", 'WARNING')
            return
        
        for ip, device in self.devices.items():
            open_ports = {s.port for s in device.services}
            
            analyzers = {
                502:   ('Modbus TCP',    ModbusTCPAnalyzer(ip, 502, self.assessor.timeout)),
                20000: ('DNP3',          DNP3Analyzer(ip, 20000, self.assessor.timeout)),
                2404:  ('IEC 104',       IEC104Analyzer(ip, 2404, self.assessor.timeout)),
                4840:  ('OPC UA',        OPCUAAnalyzer(ip, 4840, self.assessor.timeout)),
                44818: ('EtherNet/IP',   EtherNetIPAnalyzer(ip, 44818, self.assessor.timeout)),
                1883:  ('MQTT',          MQTTAnalyzer(ip, 1883, self.assessor.timeout)),
                47808: ('BACnet/IP',     BACnetAnalyzer(ip, 47808, self.assessor.timeout)),
                102:   ('S7/TPKT',       S7Analyzer(ip, 102, self.assessor.timeout)),
            }
            
            for port, (proto_name, analyzer) in analyzers.items():
                if port in open_ports:
                    status(f"{ip}: Analyzing {proto_name} (port {port})", 'SCAN')
                    try:
                        result = analyzer.full_assessment()
                        if result.success:
                            status(f"{ip}: {proto_name} - SUCCESS", 'SUCCESS')
                            if result.data:
                                for k, v in list(result.data.items())[:3]:
                                    cprint(f"    {Colors.BORDER}{k}:{Colors.RESET} "
                                           f"{Colors.DATA_DIM}{str(v)[:80]}{Colors.RESET}")
                        else:
                            if result.error:
                                self.logger.scan(f"{ip}: {proto_name} - {result.error}")
                    except Exception as e:
                        self.logger.error(f"{ip}: {proto_name} error: {e}")
    
    def run_plc_assessment(self):
        """Run full PLC security assessment on all discovered devices."""
        if not self.devices:
            status("No devices to assess. Run discovery first.", 'WARNING')
            return
        
        for ip, device in self.devices.items():
            # Only assess ICS-relevant devices
            if (device.device_type in [DeviceType.PLC, DeviceType.RTU,
                                       DeviceType.HMI, DeviceType.SCADA,
                                       DeviceType.IED, DeviceType.IIOT]
                    or device.protocols):
                vulns = self.assessor.full_assessment(ip, device)
                self.vulns.extend(vulns)
    
    def run_full(self):
        """Run complete assessment pipeline."""
        status("Starting FULL OT/ICS Assessment", 'INFO')
        print(f"  {Colors.WARNING}⚠  Ensure you have written authorization!{Colors.RESET}\n")
        
        self.run_discovery()
        
        if self.devices:
            self.run_protocol_analysis()
            self.run_plc_assessment()
            self.generate_reports()
        else:
            status("No devices found. Check network range and connectivity.", 'WARNING')
    
    def generate_reports(self):
        """Generate assessment reports."""
        scan_config = {
            'network':   getattr(self.args, 'network', 'N/A'),
            'start_time': self.start_ts.isoformat(),
            'end_time':   datetime.now().isoformat(),
            'duration':   str(datetime.now() - self.start_ts),
        }
        
        reporter = ReportGenerator(self.devices, self.vulns, scan_config)
        reports  = reporter.generate_all()
        
        print(f"\n  {Colors.SUCCESS}Reports generated:{Colors.RESET}")
        for fmt, path in reports.items():
            print(f"    {Colors.DATA}{fmt.upper():5s}{Colors.RESET} → "
                  f"{Colors.INFO}{path}{Colors.RESET}")
    
    def _print_discovery_summary(self):
        """Print discovery summary table."""
        print_section("DISCOVERY SUMMARY")
        
        if not self.devices:
            return
        
        headers = ['IP', 'Type', 'Vendor', 'Protocols', 'Ports', 'Hostname']
        rows = []
        col_colors = [Colors.IP_ADDR, Colors.WARNING, Colors.DEVICE,
                      Colors.PROTO, Colors.PORT, Colors.DATA_DIM]
        
        for ip, dev in sorted(self.devices.items()):
            rows.append([
                ip,
                dev.device_type.value[:20],
                (dev.vendor or 'Unknown')[:20],
                ', '.join(dev.protocols[:3]) or 'N/A',
                ', '.join(str(s.port) for s in dev.services[:5]) or 'None',
                (dev.hostname or 'N/A')[:20]
            ])
        
        print_table(headers, rows, col_colors)


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE MENU
# ─────────────────────────────────────────────────────────────────────────────

class InteractiveMenu:
    """Interactive CLI menu for the OT framework."""
    
    def __init__(self):
        self.framework: Optional[OTFramework] = None
        self.args = argparse.Namespace(
            network='192.168.1.0/24',
            interface=None,
            timeout=3.0,
            threads=50,
            full_scan=False,
            verbose=False,
            log_file='ot_framework.log',
            duration=60,
        )
    
    def _prompt(self, msg: str, default: str = '') -> str:
        """Colored input prompt."""
        try:
            val = input(f"  {Colors.PROMPT}[?]{Colors.RESET} {msg}"
                        f"{f' [{Colors.DATA}{default}{Colors.RESET}]' if default else ''}"
                        f"{Colors.PROMPT} > {Colors.RESET}")
            return val.strip() or default
        except (KeyboardInterrupt, EOFError):
            print()
            return default
    
    def _confirm(self, msg: str) -> bool:
        """Yes/no confirmation prompt."""
        val = self._prompt(f"{msg} (y/N)").lower()
        return val in ['y', 'yes']
    
    def print_main_menu(self):
        """Print the main menu."""
        print(f"\n{Colors.BORDER}  ╔{'═'*55}╗")
        print(f"  ║{Colors.HEADER}{'MAIN MENU':^55}{Colors.BORDER}║")
        print(f"  ╠{'═'*55}╣")
        
        menu_items = [
            ('1', 'Asset Discovery        ', 'Network scan & fingerprinting'),
            ('2', 'Protocol Analysis      ', 'Industrial protocol deep-dive'),
            ('3', 'PLC Security Assess    ', 'Full PLC/RTU/HMI assessment'),
            ('4', 'Full Assessment        ', 'Complete pipeline (1+2+3)'),
            ('5', 'Passive Monitoring     ', 'Read-only traffic analysis'),
            ('6', 'Generate Reports       ', 'Export JSON/CSV/HTML'),
            ('7', 'Configuration          ', 'Targets, options, timeouts'),
            ('8', 'Protocol Reference     ', 'ICS protocol information'),
            ('0', 'Exit                   ', ''),
        ]

        for num, label, desc in menu_items:
            # Build the visible text and measure it, then pad to fixed box width
            visible = f"  {num}  {label}  {desc}"
            pad = max(0, 53 - len(visible))
            print(f"  {Colors.BORDER}║  {Colors.MENU_NUM}{num}{Colors.RESET}  "
                  f"{Colors.MENU_TEXT}{label}{Colors.RESET}  "
                  f"{Colors.SEPARATOR}{desc}{Colors.RESET}"
                  f"{' ' * pad}{Colors.BORDER}║")
        
        print(f"  ╚{'═'*55}╝{Colors.RESET}")
        
        # Current config
        print(f"\n  {Colors.BORDER}Target:{Colors.RESET} {Colors.IP_ADDR}{self.args.network}{Colors.RESET}"
              f"  {Colors.BORDER}Timeout:{Colors.RESET} {Colors.DATA}{self.args.timeout}s{Colors.RESET}"
              f"  {Colors.BORDER}Threads:{Colors.RESET} {Colors.DATA}{self.args.threads}{Colors.RESET}")
    
    def configure(self):
        """Configuration menu."""
        print_section("CONFIGURATION")
        
        network = self._prompt("Target network/IP (CIDR)", self.args.network)
        self.args.network = network
        
        iface = self._prompt("Network interface (leave blank for auto)", 
                             self.args.interface or '')
        self.args.interface = iface or None
        
        timeout = self._prompt("Connection timeout (seconds)", str(self.args.timeout))
        try:
            self.args.timeout = float(timeout)
        except ValueError:
            pass
        
        threads = self._prompt("Scan threads", str(self.args.threads))
        try:
            self.args.threads = int(threads)
        except ValueError:
            pass
        
        full = self._confirm("Full port scan (1-65535)? (slower but thorough)")
        self.args.full_scan = full
        
        verbose = self._confirm("Verbose output?")
        self.args.verbose = verbose
        
        status("Configuration updated", 'SUCCESS')
    
    def show_protocol_reference(self):
        """Show ICS protocol reference information."""
        print_section("INDUSTRIAL PROTOCOL REFERENCE")
        
        protocols = [
            ('Modbus TCP',          'TCP 502',    'PLC/RTU',    'CRITICAL', 'No auth, read/write registers'),
            ('Modbus RTU',          'Serial',     'PLC/RTU',    'CRITICAL', 'Serial variant of Modbus'),
            ('DNP3',                'TCP 20000',  'RTU/IED',    'HIGH',     'SCADA/substations, SAv5 optional'),
            ('IEC 60870-5-104',     'TCP 2404',   'RTU/IED',    'HIGH',     'Telecontrol, no native auth'),
            ('IEC 61850/MMS',       'TCP 102',    'IED',        'HIGH',     'Substation automation'),
            ('OPC DA',              'TCP 135',    'SCADA',      'CRITICAL', 'DCOM-based, Windows only'),
            ('OPC UA',              'TCP 4840',   'SCADA',      'MEDIUM',   'Modern, security policies'),
            ('BACnet/IP',           'UDP 47808',  'BMS',        'MEDIUM',   'Building automation'),
            ('EtherNet/IP/CIP',     'TCP 44818',  'PLC',        'HIGH',     'Rockwell/Allen-Bradley'),
            ('Profinet',            'UDP 34964',  'PLC',        'HIGH',     'Siemens-dominated'),
            ('S7 Protocol',         'TCP 102',    'PLC',        'CRITICAL', 'Siemens S7 family'),
            ('MQTT',                'TCP 1883',   'IIoT',       'HIGH',     'Often no auth, pub/sub'),
            ('CAN Bus',             'Gateway',    'IIoT/OT',    'MEDIUM',   'Vehicle/embedded systems'),
            ('M-Bus',               'TCP 2351',   'Metering',   'MEDIUM',   'Energy meters'),
            ('OMRON FINS',          'TCP 9600',   'PLC',        'HIGH',     'Omron PLCs, no auth'),
            ('Mitsubishi MELSEC',   'TCP 5006',   'PLC',        'HIGH',     'Mitsubishi PLCs'),
        ]
        
        headers = ['Protocol', 'Port', 'Device', 'Risk', 'Notes']
        rows    = [[p[0], p[1], p[2], p[3], p[4]] for p in protocols]
        col_c   = [Colors.PROTO, Colors.PORT, Colors.DEVICE,
                   Colors.VULN, Colors.DATA_DIM]
        print_table(headers, rows, col_c)
    
    def run(self):
        """Main interactive loop."""
        print_banner()
        
        # Legal disclaimer
        print(f"  {Colors.WARNING}{'═'*73}")
        print(f"  LEGAL DISCLAIMER: This tool is for AUTHORIZED security testing only.")
        print(f"  Unauthorized use is illegal. Ensure written permission before testing.")
        print(f"  {'═'*73}{Colors.RESET}")
        
        if not self._confirm("\n  I confirm I have WRITTEN AUTHORIZATION to test the target systems"):
            print(f"\n  {Colors.ERROR}Authorization not confirmed. Exiting.{Colors.RESET}\n")
            sys.exit(0)
        
        while True:
            self.print_main_menu()
            
            choice = self._prompt("Select option")
            
            if not self.framework:
                self.framework = OTFramework(self.args)
            else:
                # Refresh framework with current args
                self.framework.args = self.args
                self.framework.discovery.timeout = self.args.timeout
                self.framework.discovery.threads = self.args.threads
                self.framework.assessor.timeout  = self.args.timeout
            
            if choice == '0':
                print(f"\n  {Colors.INFO}Exiting OT Framework. Goodbye.{Colors.RESET}\n")
                break
            
            elif choice == '1':
                self.framework.run_discovery()
            
            elif choice == '2':
                if not self.framework.devices:
                    target = self._prompt("Single target IP for protocol analysis")
                    if target:
                        # Add a dummy device for the target
                        dev = IndustrialDevice(ip=target)
                        # Quick port scan
                        status(f"Quick port scan on {target}", 'SCAN')
                        svcs = self.framework.discovery.port_scan(target)
                        dev.services = svcs
                        self.framework.devices[target] = dev
                self.framework.run_protocol_analysis()
            
            elif choice == '3':
                if not self.framework.devices:
                    status("Run discovery first (option 1)", 'WARNING')
                else:
                    self.framework.run_plc_assessment()
            
            elif choice == '4':
                self.framework.run_full()
            
            elif choice == '5':
                iface = self._prompt("Interface for passive monitoring", "eth0")
                self.args.interface = iface
                dur = self._prompt("Duration (seconds)", "60")
                try:
                    self.args.duration = int(dur)
                except ValueError:
                    pass
                self.framework.run_passive()
            
            elif choice == '6':
                if not self.framework.devices and not self.framework.vulns:
                    status("No data to report. Run a scan first.", 'WARNING')
                else:
                    self.framework.generate_reports()
            
            elif choice == '7':
                self.configure()
                self.framework = OTFramework(self.args)  # Reinit with new config
            
            elif choice == '8':
                self.show_protocol_reference()
            
            else:
                status(f"Invalid option: {choice}", 'WARNING')
            
            try:
                input(f"\n  {Colors.SEPARATOR}Press ENTER to continue...{Colors.RESET}")
            except (KeyboardInterrupt, EOFError):
                pass


# ─────────────────────────────────────────────────────────────────────────────
# CLI ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='ot_framework.py',
        description='OT/ICS Industrial Penetration Testing Framework v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Interactive mode (recommended):
  python3 ot_framework.py

  # Full automated scan:
  python3 ot_framework.py --mode full --network 192.168.1.0/24

  # Discovery only:
  python3 ot_framework.py --mode discover --network 10.0.0.0/24

  # Protocol analysis on single host:
  python3 ot_framework.py --mode protocol --network 192.168.1.100/32

  # PLC assessment:
  python3 ot_framework.py --mode plc --network 192.168.1.0/24

  # Passive monitoring:
  python3 ot_framework.py --mode passive --interface eth0 --duration 120

  # Fast scan with custom threads:
  python3 ot_framework.py --mode full --network 10.0.0.0/16 --threads 100 --timeout 1

COMPILE/INSTALL:
  # Install dependencies:
  pip3 install colorama scapy netifaces pymodbus

  # Make executable:
  chmod +x ot_framework.py

  # Build standalone binary (optional):
  pip3 install pyinstaller
  pyinstaller --onefile ot_framework.py
  ./dist/ot_framework

  # Root required for ARP/raw socket features:
  sudo python3 ot_framework.py
        """
    )
    
    parser.add_argument('--mode', choices=['interactive', 'full', 'discover',
                                            'protocol', 'plc', 'passive', 'report'],
                         default='interactive', help='Operation mode')
    
    target_grp = parser.add_argument_group('Target Options')
    target_grp.add_argument('--network',   '-n', default='192.168.1.0/24',
                             help='Target network in CIDR notation or single IP')
    target_grp.add_argument('--interface', '-i', default=None,
                             help='Network interface for scanning')
    
    scan_grp = parser.add_argument_group('Scan Options')
    scan_grp.add_argument('--timeout',   '-t', type=float, default=2.0,
                           help='Connection timeout (seconds)')
    scan_grp.add_argument('--threads',   '-T', type=int,   default=50,
                           help='Number of parallel threads')
    scan_grp.add_argument('--full-scan', '-F', action='store_true',
                           help='Full port scan (1-65535)')
    scan_grp.add_argument('--duration',  '-d', type=int,   default=60,
                           help='Passive monitoring duration (seconds)')
    
    output_grp = parser.add_argument_group('Output Options')
    output_grp.add_argument('--output',   '-o', default=None,
                             help='Output file prefix')
    output_grp.add_argument('--log-file',       default='ot_framework.log',
                             help='Log file path')
    output_grp.add_argument('--verbose',  '-v', action='store_true',
                             help='Verbose output')
    output_grp.add_argument('--no-color',       action='store_true',
                             help='Disable color output')
    
    return parser


# ─────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Main entrypoint."""
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print(f"\n\n  {Colors.WARNING}[!] Interrupted by user. "
              f"Saving partial results...{Colors.RESET}")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = build_parser()
    args   = parser.parse_args()
    
    # Disable colors if requested
    if getattr(args, 'no_color', False):
        for attr in dir(Fore):
            if not attr.startswith('_'):
                setattr(Fore, attr, '')
        for attr in dir(Back):
            if not attr.startswith('_'):
                setattr(Back, attr, '')
        for attr in dir(Style):
            if not attr.startswith('_'):
                setattr(Style, attr, '')
    
    if args.mode == 'interactive':
        menu = InteractiveMenu()
        menu.run()
    else:
        # Non-interactive modes
        print_banner()
        
        # Confirm authorization
        if sys.stdin.isatty():
            confirm = input(
                f"  {Colors.WARNING}[AUTH] Confirm written authorization to test "
                f"{args.network} (y/N): {Colors.RESET}"
            ).strip().lower()
            if confirm not in ['y', 'yes']:
                print(f"  {Colors.ERROR}Authorization not confirmed. Exiting.{Colors.RESET}")
                sys.exit(0)
        
        framework = OTFramework(args)
        
        mode_map = {
            'full':     framework.run_full,
            'discover': framework.run_discovery,
            'protocol': lambda: (framework.run_discovery(), framework.run_protocol_analysis()),
            'plc':      lambda: (framework.run_discovery(), framework.run_plc_assessment()),
            'passive':  framework.run_passive,
            'report':   framework.generate_reports,
        }
        
        fn = mode_map.get(args.mode)
        if fn:
            fn()
        
        # Print final stats
        elapsed = datetime.now() - framework.start_ts
        print(f"\n  {Colors.SUCCESS}Scan complete in {elapsed}{Colors.RESET}")
        print(f"  {Colors.DATA}Devices: {len(framework.devices)}"
              f"  Vulnerabilities: {len(framework.vulns)}{Colors.RESET}\n")


if __name__ == '__main__':
    main()