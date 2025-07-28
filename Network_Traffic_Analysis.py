import socket
import ssl
import struct
import time

# Global dictionary to track statistics
summary_stats = {
    "total_packets": 0,
    "http": 0,
    "https": 0,
    "dns": 0,
    "anomalies": 0,
    "compliance_failures": 0,
    "security_alerts": 0
}

def reset_summary():
    """
    Reset the summary statistics before each new run.
    """
    for key in summary_stats:
        summary_stats[key] = 0

def create_ssl_context():
    """
    Create an SSL context with default settings.
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    return context

def packet_inspection(data):
    """
    Packet Inspection: Examining individual data packets to understand their content,
    source, destination, and other relevant information.
    """
    if len(data) < 14:
        print("  Warning: Packet too short for Ethernet header")
        return False
        
    eth_header = struct.unpack('!6s6sH', data[:14])
    eth_dst = ':'.join(f"{b:02x}" for b in eth_header[0])
    eth_src = ':'.join(f"{b:02x}" for b in eth_header[1])
    eth_type = eth_header[2]  # Fixed: Use actual EtherType

    print(f"Packet Inspection - Ethernet Frame:")
    print(f"  Source MAC: {eth_src}")
    print(f"  Destination MAC: {eth_dst}")
    print(f"  EtherType: {hex(eth_type)}")

    # Only process IP packets
    if eth_type != 0x0800:
        print(f"  Non-IP packet (EtherType: {hex(eth_type)})")
        return False

    if len(data) < 34:
        print("  Warning: Packet too short for IP header")
        return False

    ip_header = struct.unpack('!BBHHHBBH4s4s', data[14:34])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    # Defensive check for malformed headers
    if ihl < 5 or version != 4:
        print(f"  Warning: Invalid IP header (Version: {version}, IHL: {ihl})")
        return False

    ip_src = socket.inet_ntoa(ip_header[8])
    ip_dst = socket.inet_ntoa(ip_header[9])

    print(f"  IP Header:")
    print(f"    Version: {version}")
    print(f"    IHL: {ihl}")
    print(f"    Source IP: {ip_src}")
    print(f"    Destination IP: {ip_dst}")
    
    return True

def protocol_analysis(data):
    """
    Protocol Analysis: Understanding the protocols used for communication within the network.
    Different protocols have specific structures and rules.
    """
    if len(data) < 14:
        return
        
    eth_header = struct.unpack('!6s6sH', data[:14])
    eth_type = eth_header[2]
    
    print(f"Protocol Analysis -")
    print(f"  EtherType: {hex(eth_type)}")

    # Only analyze IP packets
    if eth_type != 0x0800:
        print("  Non-IP packet - skipping protocol analysis")
        return

    if len(data) < 34:
        return

    ip_header = struct.unpack('!BBHHHBBH4s4s', data[14:34])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    # Defensive check for malformed headers
    if ihl < 5 or version != 4:
        print("  Warning: Invalid IP header in protocol analysis")
        return

    protocol = ip_header[6]
    print(f"  IP Protocol: {protocol}")

    if protocol == 6:  # TCP
        if len(data) < 54:
            print("  Warning: Packet too short for TCP header")
            return
            
        tcp_header = struct.unpack('!HHIIBBHHH', data[34:54])
        tcp_sport = tcp_header[0]
        tcp_dport = tcp_header[1]

        print(f"  TCP Header:")
        print(f"    Source Port: {tcp_sport}")
        print(f"    Destination Port: {tcp_dport}")

        # Check both source and destination ports
        if tcp_dport == 80 or tcp_sport == 80:
            print("    HTTP Protocol")
            summary_stats["http"] += 1
        elif tcp_dport == 443 or tcp_sport == 443:
            print("    HTTPS Protocol")
            summary_stats["https"] += 1
        elif tcp_dport == 53 or tcp_sport == 53:
            print("    DNS over TCP Protocol")
            summary_stats["dns"] += 1
        else:
            print("    Other TCP protocol")

    elif protocol == 17:  # UDP
        if len(data) < 42:
            print("  Warning: Packet too short for UDP header")
            return
            
        udp_header = struct.unpack('!HHHH', data[34:42])
        udp_sport = udp_header[0]
        udp_dport = udp_header[1]

        print(f"  UDP Header:")
        print(f"    Source Port: {udp_sport}")
        print(f"    Destination Port: {udp_dport}")

        # DNS typically uses UDP
        if udp_dport == 53 or udp_sport == 53:
            print("    DNS Protocol")
            summary_stats["dns"] += 1
        else:
            print("    Other UDP protocol")

def anomaly_detection(data):
    """
    Anomaly Detection: Identifying deviations from normal network behavior.
    This can include unusual patterns of data flow, unexpected spikes in traffic,
    or irregular communication between network nodes.
    """
    if len(data) > 1500:
        print("Anomaly Detected - Unusual packet length")
        summary_stats["anomalies"] += 1

def security_monitoring(data):
    """
    Security Monitoring: Monitoring network traffic for signs of malicious activity,
    such as unauthorized access, data exfiltration, or malware communication.
    """
    if b'x3!Kp2zL9wQv' in data:
        log_security_alert("Malicious Pattern Detected", data)
        take_security_action(data)

def log_security_alert(alert_message, data):
    """
    Log the security alert.
    """
    with open("security_alerts.log", "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        f.write(f"{timestamp}: {alert_message}\n")
    summary_stats["security_alerts"] += 1

def take_security_action(data):
    """
    Take appropriate security action in response to the detected security threat.
    """
    notify_security_team(data)

def notify_security_team(data):
    """
    Notify the security team about the detected security threat.
    """
    print("Security Alert: Malicious pattern detected. Notifying security team...")

def performance_monitoring():
    """
    Performance Monitoring: Analyzing network traffic helps in assessing and optimizing
    the performance of the network. This includes identifying bottlenecks,
    optimizing data flow, and ensuring that the network meets its performance requirements.
    """
    latency = 50
    print(f"Performance Monitoring - Network Latency: {latency} ms")

def forensic_analysis():
    """
    Forensic Analysis: After a security incident or network outage,
    NTA can be used to conduct forensic analysis to understand the events leading to the issue.
    This helps in identifying the root cause and implementing measures to prevent similar incidents in the future.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"Forensic Analysis - Event Timestamp: {timestamp}")

def compliance_monitoring(data):
    """
    Compliance Monitoring: Simulate checks for compliance with regulations or standards.
    """
    passed = True
    if b'firewall_enabled' not in data:
        print("Compliance Alert - Firewall not enabled")
        passed = False
    if b'encryption_in_transit' not in data:
        print("Compliance Alert - Encryption in transit not enforced")
        passed = False

    if not passed:
        summary_stats["compliance_failures"] += 1

    if passed:
        print("Compliance Monitoring - Network is compliant with regulations")
    else:
        print("Compliance Monitoring - Network is not fully compliant")

def simulate_ssl_decryption(data):
    """
    Simulate SSL/TLS decryption.
    This is where you would integrate your SSL/TLS decryption logic.
    """
    return data

def print_summary():
    """
    Print a summary of the packet analysis after execution.
    """
    print("\n--- Summary ---")
    print(f"Total Packets Captured: {summary_stats['total_packets']}")
    print(f"HTTP Packets: {summary_stats['http']}")
    print(f"HTTPS Packets: {summary_stats['https']}")
    print(f"DNS Packets: {summary_stats['dns']}")
    print(f"Anomalies: {summary_stats['anomalies']}")
    print(f"Compliance Failures: {summary_stats['compliance_failures']}")
    print(f"Security Alerts Logged: {summary_stats['security_alerts']}")

def capture_traffic(interface='eth0', count=5, use_ssl=False):
    """
    Function to capture network traffic on the specified interface.
    """
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((interface, 0))
        print(f"Capturing {count} packets on interface {interface}...")

        for i in range(count):
            data, _ = raw_socket.recvfrom(65535)
            if data:
                summary_stats["total_packets"] += 1
                print(f"\n--- Processing Packet {i + 1} ---")

                if use_ssl:
                    decrypted_data = simulate_ssl_decryption(data)
                    if packet_inspection(decrypted_data):
                        protocol_analysis(decrypted_data)
                        anomaly_detection(decrypted_data)
                        compliance_monitoring(decrypted_data)
                        security_monitoring(decrypted_data)
                else:
                    if packet_inspection(data):
                        protocol_analysis(data)
                        anomaly_detection(data)
                        compliance_monitoring(data)
                        security_monitoring(data)

    except PermissionError:
        print("Error: Need root privileges to capture raw packets")
    except KeyboardInterrupt:
        print("Capture stopped by user.")
    except Exception as e:
        print(f"Error during packet capture: {e}")
    finally:
        try:
            raw_socket.close()
        except:
            pass

if __name__ == "__main__":
    reset_summary()
    capture_traffic(interface='ens33', count=5, use_ssl=False)
    capture_traffic(interface='ens33', count=5, use_ssl=True)
    performance_monitoring()
    forensic_analysis()
    print_summary()