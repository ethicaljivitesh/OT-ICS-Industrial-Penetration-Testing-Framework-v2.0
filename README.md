<div align="center">

```
 ██████╗ ████████╗    ██████╗ ███████╗███╗   ██╗    ████████╗███████╗
██╔═══██╗╚══██╔══╝    ██╔══██╗██╔════╝████╗  ██║    ╚══██╔══╝██╔════╝
██║   ██║   ██║       ██████╔╝█████╗  ██╔██╗ ██║       ██║   █████╗  
██║   ██║   ██║       ██╔═══╝ ██╔══╝  ██║╚██╗██║       ██║   ██╔══╝  
╚██████╔╝   ██║       ██║     ███████╗██║ ╚████║       ██║   ██║     
 ╚═════╝    ╚═╝       ╚═╝     ╚══════╝╚═╝  ╚═══╝       ╚═╝   ╚═╝     
```

# OT/ICS Industrial Penetration Testing Framework
### **v2.0** — Advanced Industrial Security Assessment Platform

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://kernel.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Authorized](https://img.shields.io/badge/Use-Authorized%20Only-red?style=for-the-badge&logo=shield&logoColor=white)]()
[![Kali](https://img.shields.io/badge/Kali%20Linux-Supported-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)

<br>

> **The most comprehensive open-source OT/ICS security assessment framework.**  
> Single-file Python tool covering asset discovery, 15+ industrial protocols,  
> PLC firmware analysis, and professional vulnerability reporting.

<br>

**Protocols Supported:**

`Modbus TCP` · `Modbus RTU` · `DNP3` · `IEC 60870-5-104` · `IEC 61850` · `OPC DA` · `OPC UA`  
`BACnet/IP` · `Profinet` · `EtherNet/IP` · `CIP` · `S7 Protocol` · `MQTT` · `CAN Bus` · `M-Bus`

<br>

**Targets:**

`PLC` · `RTU` · `HMI` · `SCADA Servers` · `IEDs` · `Industrial Switches` · `IIoT Devices` · `Historians`

</div>

---

> [!CAUTION]
> **⚠️ LEGAL DISCLAIMER — READ BEFORE USE**
>
> This framework is designed **exclusively** for **authorized** security assessments, penetration testing engagements, academic research, and controlled lab environments.
>
> - ✅ Use on systems **you own**
> - ✅ Use with **explicit written authorization** from the asset owner
> - ✅ Use in **isolated lab/test environments**
> - ❌ **Never** use on live production OT networks without change-freeze approval
> - ❌ **Never** use on systems you do not have permission to test
>
> Unauthorized use violates the **Computer Fraud and Abuse Act (CFAA)**, **Computer Misuse Act (UK)**, **EU Directive 2013/40/EU**, and equivalent laws worldwide. The authors assume **zero liability** for misuse.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
- [Build Standalone Binary](#-build-standalone-binary)
- [Usage — Interactive Mode](#-usage--interactive-mode)
- [Usage — CLI Mode](#-usage--cli-mode)
- [Protocol Coverage](#-protocol-coverage)
- [Vulnerability Checks](#-vulnerability-checks)
- [Output & Reports](#-output--reports)
- [Test Lab Setup](#-test-lab-setup)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Asset Discovery
- **ICMP ping sweep** with TCP fallback
- **ARP scanning** (scapy-powered, no nmap required)
- **Active TCP/UDP port scanning** — ICS-optimized port list
- **OUI-based vendor identification** — 30+ industrial vendors
- **Banner grabbing** and service fingerprinting
- **Passive network monitoring** — zero active probes
- **ASCII network topology mapping**
- **Multi-threaded** — up to 200 parallel threads

</td>
<td width="50%">

### ⚡ Protocol Analysis
- **15 industrial protocols** supported natively
- **Modbus TCP** — register/coil read, unit ID scan, MEI
- **Siemens S7** — COTP/TPKT, SZL read, CPU identification
- **EtherNet/IP** — List Identity, vendor/product extraction
- **DNP3** — SAv5 auth check, link status probing
- **IEC 60870-5-104** — STARTDT, General Interrogation
- **OPC UA** — Hello/ACK, security policy enumeration
- **MQTT** — Anonymous access, default credential testing
- **BACnet/IP** — WhoIs broadcast, ReadProperty

</td>
</tr>
<tr>
<td width="50%">

### 🔐 PLC Security Assessment
- **Unauthenticated read/write** access detection
- **Default credential** brute-forcing (20+ common pairs)
- **Modbus write access** verification (non-destructive)
- **S7 protection level** assessment
- **SNMP community string** enumeration (10+ defaults)
- **Firmware version** disclosure detection
- **Anonymous FTP** access testing
- **Telnet/cleartext** service detection
- **Web management interface** fingerprinting

</td>
<td width="50%">

### 📊 Reporting
- **JSON** — Full machine-readable report with all findings
- **CSV** — Vulnerability spreadsheet (Excel-compatible)
- **HTML** — Professional dark-theme visual report
- **CVSS scoring** for all vulnerability findings
- **Severity ratings** — CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Remediation guidance** per finding
- **Timestamped** output files
- **Structured log** file (ot_framework.log)

</td>
</tr>
</table>

---

## 🏗 Architecture

```
ot_framework.py  (~3,200 lines · Single file · Zero external ICS libs required)
│
├── 🗄  FingerprintDB          OUI→vendor map, port→protocol map, banner signatures
│
├── 🌐 AssetDiscovery          Ping sweep · ARP · Port scan · UDP · Passive · Topology
│
├── 📡 Protocol Analyzers
│   ├── ModbusTCPAnalyzer      FC01/02/03/04/05/06/2B · Unit ID scan · Write check
│   ├── DNP3Analyzer           CRC-16 · Link frames · SAv5 auth detection
│   ├── IEC104Analyzer         APCI/APDU · STARTDT · General Interrogation
│   ├── OPCUAAnalyzer          Hello/ACK · Endpoint enumeration
│   ├── EtherNetIPAnalyzer     List Identity (TCP+UDP) · CIP device info
│   ├── S7Analyzer             TPKT · COTP CR/CC · Setup Comm · SZL 0x0011
│   ├── MQTTAnalyzer           CONNECT · CONNACK · Anonymous + cred testing
│   └── BACnetAnalyzer         BVLC · NPDU · WhoIs broadcast · ReadProperty
│
├── 🔐 PLCSecurityAssessor     Multi-protocol vuln engine · CVSS · Remediation
│
├── 📊 ReportGenerator         JSON · CSV · HTML (dark theme)
│
├── 🎛  OTFramework            Main pipeline controller
│
└── 🖥  InteractiveMenu        Full-color CLI menu interface
```

---

## 💻 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Linux (any modern distro) | Kali Linux 2023+ / Ubuntu 22.04 |
| **Python** | 3.8 | 3.11+ |
| **RAM** | 512 MB | 2 GB |
| **Privileges** | User (limited) | **root/sudo** (full features) |
| **Network** | Layer 3 access | Layer 2 access (ARP scan) |

> **Root is required for:** ARP scanning, raw socket features, passive traffic capture (scapy/tcpdump).  
> Most active scanning features work without root but with reduced capability.

---

## 🚀 Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/youruser/ot-pen-framework.git
cd ot-pen-framework
```

### Step 2 — Install Python Dependencies

```bash
pip3 install colorama scapy netifaces pymodbus opcua bacpypes
```

Or install everything at once from requirements:

```bash
pip3 install -r requirements.txt
```

<details>
<summary><b>requirements.txt (click to expand)</b></summary>

```
colorama>=0.4.6
scapy>=2.5.0
netifaces>=0.11.0
pymodbus>=3.0.0
opcua>=0.98.13
bacpypes>=0.18.6
```

</details>

### Step 3 — System Packages (Recommended)

```bash
# Debian / Ubuntu / Kali Linux
sudo apt-get install -y python3-pip arp-scan nmap tcpdump python3-scapy

# RHEL / CentOS / Fedora
sudo yum install -y python3-pip tcpdump nmap

# Arch Linux
sudo pacman -S python-pip tcpdump nmap
```

### Step 4 — Make Executable

```bash
chmod +x ot_framework.py
```

### Step 5 — Run

```bash
# Interactive mode (recommended for first-time use)
sudo python3 ot_framework.py

# Or directly (after chmod +x)
sudo ./ot_framework.py
```

> **Note:** The framework auto-detects and installs missing Python packages on first launch.

---

## 📦 Build Standalone Binary

Create a single portable binary using **PyInstaller** — no Python installation needed on target machine:

```bash
# Install PyInstaller
pip3 install pyinstaller

# Build single-file binary
pyinstaller --onefile \
  --name ot_framework \
  --hidden-import scapy.layers.all \
  --hidden-import colorama \
  --strip \
  ot_framework.py

# Binary output location
ls -lh dist/ot_framework
```

```bash
# Copy to system PATH (optional)
sudo cp dist/ot_framework /usr/local/bin/
sudo chmod +x /usr/local/bin/ot_framework

# Run from anywhere
sudo ot_framework
```

> Binary size: ~15–25 MB (depends on scapy inclusion).  
> Built binary is architecture-specific — build on the same OS/arch you'll run it on.

---

## 🖥 Usage — Interactive Mode

Launch the full-color interactive menu:

```bash
sudo python3 ot_framework.py
```

```
  ╔═══════════════════════════════════════════════════════╗
  ║                       MAIN MENU                       ║
  ╠═══════════════════════════════════════════════════════╣
  ║  1  Asset Discovery        Network scan & fingerprint ║
  ║  2  Protocol Analysis      Industrial protocol deep   ║
  ║  3  PLC Security Assess    Full PLC/RTU/HMI assess    ║
  ║  4  Full Assessment        Complete pipeline (1+2+3)  ║
  ║  5  Passive Monitoring     Read-only traffic analysis  ║
  ║  6  Generate Reports       Export JSON/CSV/HTML       ║
  ║  7  Configuration          Targets, options, timeouts ║
  ║  8  Protocol Reference     ICS protocol information   ║
  ║  0  Exit                                              ║
  ╚═══════════════════════════════════════════════════════╝

  Target: 192.168.1.0/24  Timeout: 3.0s  Threads: 50
```

**Menu options explained:**

| Option | Description |
|--------|-------------|
| `1` Asset Discovery | Runs ping sweep → ARP scan → port scan → device fingerprinting → topology map |
| `2` Protocol Analysis | Probes each discovered device with its detected protocols |
| `3` PLC Security Assess | Full vulnerability assessment — checks auth, defaults, write access, firmware |
| `4` Full Assessment | Runs options 1 + 2 + 3 in sequence, then generates all reports |
| `5` Passive Monitoring | Listens on a network interface with zero active probes (safe for live OT) |
| `6` Generate Reports | Exports JSON, CSV, and HTML reports from current scan data |
| `7` Configuration | Change target network, interface, threads, timeout, scan depth |
| `8` Protocol Reference | Quick reference table for all 15 supported ICS protocols |

---

## ⌨️ Usage — CLI Mode

For automation, CI pipelines, or scripted assessments:

### Full Automated Assessment
```bash
sudo python3 ot_framework.py --mode full --network 192.168.1.0/24
```

### Asset Discovery Only
```bash
sudo python3 ot_framework.py --mode discover --network 10.0.0.0/24
```

### Protocol Analysis on Single Host
```bash
sudo python3 ot_framework.py --mode protocol --network 192.168.1.50/32
```

### PLC Security Assessment
```bash
sudo python3 ot_framework.py --mode plc --network 192.168.1.0/24 --timeout 3
```

### Passive Network Monitoring (No Active Probes — Safe for Live OT)
```bash
sudo python3 ot_framework.py --mode passive --interface eth0 --duration 300
```

### Full Port Scan (All 65535 Ports — Thorough but Slower)
```bash
sudo python3 ot_framework.py --mode full --network 192.168.1.0/24 --full-scan
```

### High-Speed Wide-Area Scan
```bash
sudo python3 ot_framework.py --mode discover \
  --network 10.0.0.0/16 \
  --threads 200 \
  --timeout 1 \
  --verbose
```

### No Color Output (Piping / Logging)
```bash
sudo python3 ot_framework.py --mode full \
  --network 192.168.1.0/24 \
  --no-color | tee scan_$(date +%Y%m%d).txt
```

### All CLI Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--mode` | | `interactive` | `interactive` · `full` · `discover` · `protocol` · `plc` · `passive` · `report` |
| `--network` | `-n` | `192.168.1.0/24` | Target network (CIDR) or single IP |
| `--interface` | `-i` | auto | Network interface (`eth0`, `ens33`, `wlan0`) |
| `--timeout` | `-t` | `2.0` | Connection timeout in seconds |
| `--threads` | `-T` | `50` | Parallel scan threads (max ~200) |
| `--full-scan` | `-F` | off | Scan all 65535 ports (slow but thorough) |
| `--duration` | `-d` | `60` | Passive monitoring duration (seconds) |
| `--log-file` | | `ot_framework.log` | Path to activity log |
| `--verbose` | `-v` | off | Show all scan activity in real time |
| `--no-color` | | off | Disable ANSI colors (for piping/logging) |

---

## 📡 Protocol Coverage

| Protocol | Port | Layer | Transport | Capability |
|----------|------|-------|-----------|------------|
| **Modbus TCP** | 502/TCP | App | TCP | Register/coil read-write, unit ID scan, MEI device ID |
| **Modbus RTU** | Serial | App | RS-232/485 | Serial variant (via gateway detection) |
| **DNP3** | 20000/TCP | App | TCP | Auth check, link status, function code mapping |
| **IEC 60870-5-104** | 2404/TCP | App | TCP | STARTDT, General Interrogation, ASDU parsing |
| **IEC 61850 / MMS** | 102/TCP | App | TCP | MMS service detection, IED enumeration |
| **OPC DA** | 135/TCP | App | DCOM/TCP | DCOM endpoint detection |
| **OPC UA** | 4840/TCP | App | TCP | Hello/ACK, security mode enumeration |
| **BACnet/IP** | 47808/UDP | App | UDP | WhoIs broadcast, I-Am parse, ReadProperty |
| **EtherNet/IP / CIP** | 44818/TCP · 2222/UDP | App | TCP+UDP | List Identity, vendor/device/product extraction |
| **Profinet** | 34964/UDP | App | UDP | DCP identify, device detection |
| **S7 Protocol** | 102/TCP | App | TPKT/COTP | COTP CR, setup comm, SZL read (CPU info) |
| **MQTT** | 1883/TCP | App | TCP | CONNECT, CONNACK, anonymous + credential check |
| **CAN Bus** | Gateway | Bus | CAN | Gateway detection, frame analysis |
| **M-Bus** | 2351/TCP | App | TCP | Meter detection, data frame capture |
| **SNMP** | 161/UDP | App | UDP | Community string brute-force, sysDescr read |

---

## 🔐 Vulnerability Checks

### Critical Severity
| Check ID | Description |
|----------|-------------|
| `MODBUS-001` | Modbus TCP unauthenticated read access |
| `MODBUS-002` | Modbus TCP unauthenticated write access (register/coil) |
| `S7-001` | Siemens S7 PLC accessible without password |
| `TELNET-001` | Telnet service enabled (cleartext credentials) |
| `OPC-001` | OPC DA/DCOM exposed on network perimeter |

### High Severity
| Check ID | Description |
|----------|-------------|
| `MODBUS-003` | No source address filtering on Modbus device |
| `DNP3-001` | DNP3 SAv5 authentication not enabled |
| `IEC104-001` | IEC 60870-5-104 accessible without authentication |
| `ENIP-001` | EtherNet/IP device identity exposed |
| `MQTT-001` | MQTT broker allows anonymous connection |
| `MQTT-002` | MQTT broker accepts default credentials |
| `SNMP-001` | Default SNMP community string active (public/private) |
| `FTP-001` | Anonymous FTP access enabled |
| `WEB-001` | Industrial web management interface exposed |

### Medium / Low Severity
| Check ID | Description |
|----------|-------------|
| `S7-002` | S7 CPU order number/model disclosed |
| `FW-001` | Firmware version disclosed in banner |
| `SNMP-002` | SNMPv1/v2c in use (no encryption) |
| `WEB-002` | HTTP (non-HTTPS) management interface |
| `OPCUA-001` | OPC UA security mode set to None |

---

## 📊 Output & Reports

All reports are saved in the current directory with timestamp suffixes:

```
ot_report_20240115_143022.json     ← Full machine-readable report
ot_vulns_20240115_143022.csv       ← Vulnerability spreadsheet
ot_report_20240115_143022.html     ← Visual HTML report (dark theme)
ot_framework.log                   ← Detailed activity log
```

### JSON Report Structure
```json
{
  "metadata": { "tool": "...", "timestamp": "...", "scan_config": {} },
  "summary": {
    "total_devices": 12,
    "total_vulnerabilities": 34,
    "critical": 8, "high": 14, "medium": 9, "low": 3
  },
  "devices": [ { "ip": "192.168.1.10", "device_type": "PLC", ... } ],
  "vulnerabilities": [ { "vuln_id": "MODBUS-001", "cvss": 9.8, ... } ]
}
```

### HTML Report Preview

The HTML report features:
- Dark `#0a0f1e` industrial theme
- Executive summary with severity counters
- Full device inventory table
- Vulnerability findings table with CVSS scores
- Color-coded severity badges (CRITICAL → red, HIGH → orange, MEDIUM → yellow)

---

## 🧪 Test Lab Setup

**Always test in an isolated environment before live assessments.**

### Option A — Virtual Modbus PLC (Python · Zero hardware needed)

```bash
pip3 install pymodbus

python3 -c "
from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock

store = ModbusSlaveContext(
    hr=ModbusSequentialDataBlock(0, [42] * 100),
    co=ModbusSequentialDataBlock(0, [1]  * 100),
)
ctx = ModbusServerContext(slaves=store, single=True)
print('[+] Modbus TCP server running on 0.0.0.0:502')
StartTcpServer(ctx, address=('0.0.0.0', 502))
"
```

Then scan it:
```bash
sudo python3 ot_framework.py --mode full --network 127.0.0.1/32 --timeout 5
```

### Option B — MQTT Broker (Test anonymous access)

```bash
# Install Mosquitto
sudo apt-get install -y mosquitto

# Start with anonymous access enabled (for testing)
echo "allow_anonymous true" > /tmp/mosquitto_test.conf
mosquitto -c /tmp/mosquitto_test.conf -p 1883 &

# Scan
sudo python3 ot_framework.py --mode protocol --network 127.0.0.1/32
```

### Option C — Docker ICS Lab

```bash
# Modbus + DNP3 + OPC-UA simulator
docker run -d -p 502:502 -p 20000:20000 -p 4840:4840 \
  inductiveautomation/ignition:latest

# Scan the container
sudo python3 ot_framework.py --mode full \
  --network $(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -q))/32
```

### Option D — GNS3 Network Lab

1. Install [GNS3](https://gns3.com/) with ICS appliances
2. Add Siemens PLCSIM Advanced, Schneider EcoStruxure, or OpenPLC
3. Connect the framework to the GNS3 management network
4. Run full assessment against the GNS3 subnet

---

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Permission denied` on ARP/raw socket | Not running as root | `sudo python3 ot_framework.py` |
| `scapy not found` | Missing dependency | `pip3 install scapy` |
| ARP scan returns nothing | Interface mismatch | Use `-i eth0` (or correct interface name) |
| No devices discovered | Firewall / wrong subnet | Try `--timeout 5`, verify network range |
| `cryptography not installed` warning | Optional scapy crypto | `pip3 install cryptography` (optional) |
| `ValueError: Sign not allowed` | Old version (fixed in v2.0) | Pull latest version |
| Passive capture fails | Root + scapy required | `sudo python3 ot_framework.py` |
| S7 connection refused | Wrong rack/slot | Try rack=0 slot=0, rack=0 slot=1, rack=0 slot=2 |
| Binary too large | PyInstaller includes all of scapy | Use `--exclude-module scapy` if scapy not needed |
| MQTT scan hangs | Target filtering packets | Reduce `--timeout 1` |
| HTML report not rendering | Browser blocking local file | Open via `python3 -m http.server` |

```bash
# Get network interfaces
ip link show

# Verify Python version
python3 --version

# Check if running as root
whoami

# Test basic connectivity
python3 ot_framework.py --mode discover --network 192.168.1.1/32 --timeout 5 -v
```

---

## 📁 Project Structure

```
ot-pen-framework/
├── ot_framework.py          ← Main framework (single file, ~3200 lines)
├── README.md                ← This file
├── LICENSE                  ← MIT License
├── requirements.txt         ← Python dependencies
├── OT_FRAMEWORK_GUIDE.md   ← Extended setup & compilation guide
└── examples/
    ├── modbus_server.py     ← Test Modbus server
    ├── mqtt_broker.conf     ← Test Mosquitto config
    └── lab_setup.md         ← Lab environment guide
```

---

## 🤝 Contributing

Contributions are welcome for:

- 🔌 New ICS protocol analyzers (PROFIBUS, FF HSE, HART-IP, Ethernet PowerLink)
- 🐛 Bug fixes and stability improvements
- 📡 Additional vendor fingerprints and OUI entries
- 🔐 New vulnerability checks and CVE mappings
- 📊 Additional report formats (PDF, DOCX, SARIF)
- 🧪 Lab environment configurations

**Please ensure all contributions:**
- Include only legally-cleared protocol implementations
- Follow the existing code structure and color theming
- Include a test case or lab setup instructions
- Do not include actual exploit payloads or destructive write operations

```bash
# Fork and clone
git clone https://github.com/youruser/ot-pen-framework.git

# Create a branch
git checkout -b feature/profibus-analyzer

# Submit PR against main
```

---

## 📜 License

```
MIT License — Copyright (c) 2024 OT Security Research Framework

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to deal in the Software without restriction, subject to the
condition that this software is used ONLY for authorized security testing.
```

---

## 📚 References & Standards

- [IEC 62443](https://www.iec.ch/iec62443) — Industrial Automation and Control Systems Security
- [NIST SP 800-82](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final) — Guide to OT Security
- [NERC CIP](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx) — Critical Infrastructure Protection
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — ICS Threat Framework
- [Modbus Specification](https://modbus.org/specs.php) — Modbus.org
- [DNP3 IEEE 1815](https://standards.ieee.org/ieee/1815/5414/) — DNP3 Standard
- [IEC 60870-5-104](https://webstore.iec.ch/publication/3760) — Telecontrol Protocol

---

<div align="center">

**Made for the OT/ICS security community**

*Security research · Authorized assessments · Industrial safety*

⚠️ **FOR AUTHORIZED USE ONLY** ⚠️

</div>
