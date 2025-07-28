# Network Traffic Analysis (NTA) CN-Project

A comprehensive Python-based Network Traffic Analysis tool that provides real-time monitoring and analysis of network traffic for security, performance, and compliance purposes. This tool uses raw sockets to capture and inspect Ethernet and IP packets, offering detailed insights into network behavior and potential security threats.

## 🚀 Features

### Core Functionality
- **Packet Inspection**: Deep analysis of Ethernet frames and IP headers
- **Protocol Analysis**: Detection and classification of network protocols (HTTP, HTTPS, DNS, TCP, UDP)
- **Real-time Monitoring**: Live capture and analysis of network traffic
- **Multi-protocol Support**: Handles various network protocols and packet types

### Security & Compliance
- **Anomaly Detection**: Identifies unusual network patterns and behaviors
- **Security Monitoring**: Detects malicious patterns and potential threats
- **Compliance Monitoring**: Checks network compliance with security standards
- **Security Alerting**: Logs security events and notifies administrators

### Analysis & Reporting
- **Performance Monitoring**: Network latency and performance metrics
- **Forensic Analysis**: Detailed packet-level investigation capabilities
- **SSL/TLS Support**: Framework for encrypted traffic analysis
- **Statistical Reporting**: Comprehensive traffic statistics and summaries

## 🛠️ Tech Stack

- **Language**: Python 3.x
- **Core Libraries**:
  - `socket` - Raw socket programming for packet capture
  - `ssl` - SSL/TLS encryption handling
  - `struct` - Binary data parsing and manipulation
  - `time` - Timestamp and timing operations
- **Network Protocols**: Ethernet, IPv4, TCP, UDP, HTTP, HTTPS, DNS, ARP
- **Platform**: Linux (requires raw socket support)

## 📋 Prerequisites

- **Operating System**: Linux (Ubuntu, CentOS, etc.)
- **Python**: Version 3.6 or higher
- **Privileges**: Root/sudo access (required for raw socket operations)
- **Network Interface**: Active network interface for packet capture

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/chaitra-v26/Network-Traffic-Analysis_CN-Project.git
   cd Network-Traffic-Analysis_CN-Project
   ```

2. **Verify Python installation**:
   ```bash
   python3 --version
   ```

3. **Check network interfaces**:
   ```bash
   ip addr show
   # or
   ifconfig
   ```

## 🚦 Usage

### Basic Execution

Run the network traffic analyzer with root privileges:

```bash
sudo python3 Network_Traffic_Analysis.py
```

### Configuration Options

You can modify the following parameters in the main function:

```python
# Customize these parameters
capture_traffic(interface='ens33', count=5, use_ssl=False)
```

- **interface**: Network interface name (e.g., 'eth0', 'ens33', 'wlan0')
- **count**: Number of packets to capture per session
- **use_ssl**: Enable/disable SSL decryption simulation

### Example Commands

```bash
# Basic packet capture
sudo python3 Network_Traffic_Analysis.py

# Generate test traffic (in another terminal)
curl http://example.com
curl https://google.com
nslookup google.com
ping google.com
```

## 📊 Output Analysis

### Sample Output

```
Capturing 5 packets on interface ens33...

--- Processing Packet 1 ---
Packet Inspection - Ethernet Frame:
  Source MAC: 00:0c:29:38:92:2c
  Destination MAC: 00:50:56:f1:d6:fb
  EtherType: 0x800
  IP Header:
    Version: 4
    IHL: 5
    Source IP: 192.168.44.130
    Destination IP: 57.144.147.32
Protocol Analysis -
  EtherType: 0x800
  IP Protocol: 6
  TCP Header:
    Source Port: 35582
    Destination Port: 443
    HTTPS Protocol

--- Summary ---
Total Packets Captured: 10
HTTP Packets: 2
HTTPS Packets: 5
DNS Packets: 1
Anomalies: 0
Compliance Failures: 2
Security Alerts Logged: 0
```

### Understanding Results

- **Packet Inspection**: Shows MAC addresses, IP addresses, and protocol information
- **Protocol Analysis**: Identifies application-layer protocols
- **Security Monitoring**: Reports any detected threats or anomalies
- **Summary Statistics**: Provides overview of captured traffic

## 🔍 Key Components

### 1. Packet Inspection
- Parses Ethernet frames and IP headers
- Extracts source/destination MAC and IP addresses
- Validates packet structure and integrity

### 2. Protocol Analysis
- Identifies network protocols (TCP/UDP)
- Classifies application protocols (HTTP/HTTPS/DNS)
- Analyzes port-based communication patterns

### 3. Security Features
- **Anomaly Detection**: Flags unusual packet sizes or patterns
- **Threat Detection**: Scans for known malicious signatures
- **Compliance Checks**: Validates security policy adherence

### 4. Performance Monitoring
- Network latency measurement
- Traffic volume analysis
- Performance bottleneck identification

## 🛡️ Security Considerations

- **Raw Socket Access**: Requires root privileges for packet capture
- **Network Visibility**: Can capture sensitive network traffic
- **Data Privacy**: Ensure compliance with local privacy regulations
- **Secure Storage**: Security logs are stored in `security_alerts.log`

## 🔧 Troubleshooting

### Common Issues

1. **Permission Denied**:
   ```bash
   # Solution: Run with sudo
   sudo python3 Network_Traffic_Analysis.py
   ```

2. **Network Interface Not Found**:
   ```bash
   # Check available interfaces
   ip link show
   # Update interface name in code
   ```

3. **No Packets Captured**:
   - Generate network traffic (web browsing, ping, etc.)
   - Check if interface is active and has traffic
   - Verify firewall settings

4. **Module Import Errors**:
   ```bash
   # Ensure Python 3 is being used
   python3 -c "import socket, ssl, struct, time"
   ```

## 📈 Future Enhancements

- **Web Dashboard**: Real-time web-based monitoring interface
- **Database Integration**: Store analysis results in database
- **Machine Learning**: Advanced anomaly detection using ML algorithms
- **Multi-threading**: Parallel packet processing for better performance
- **Configuration Files**: External configuration for easy customization
- **Export Features**: CSV/JSON export capabilities

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/enhancement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/enhancement`)
5. Create a Pull Request
---
