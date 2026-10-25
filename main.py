
from scapy.all import rdpcap
from collections import Counter, defaultdict

packets = rdpcap("captures/http.cap")
print("Packets captured:", len(packets))

#the counting
protocol_counts = Counter()
unique_ips = set()
unique_ports = set()

# sus points
SUSPICIOUS_PORT_THRESHOLD = 50
SUSPICIOUS_IP_THRESHOLD = 5

#differentiating bw protocols and counting unique ips and ports
for packet in packets:
    if packet.haslayer("ARP"):
        protocol_counts["ARP"] += 1
    elif packet.haslayer("TCP"):
        protocol_counts["TCP"] += 1
    elif packet.haslayer("UDP"):
        protocol_counts["UDP"] += 1
    elif packet.haslayer("ICMP"):
        protocol_counts["ICMP"] += 1
    else:
        protocol_counts["Other"] += 1

    if packet.haslayer("IP"):
        unique_ips.add(packet["IP"].dst)

    if packet.haslayer("TCP"):
        unique_ports.add(packet["TCP"].dport)
    elif packet.haslayer("UDP"):
        unique_ports.add(packet["UDP"].dport)

print("\nPacket counts by protocol:")
for protocol, count in protocol_counts.items():
    print(protocol, ":", count)

#dispkaying unique ips and ports
unique_ip_count = len(unique_ips)
unique_port_count = len(unique_ports)

print("\nUnique network entities:")
print("Unique IPs:", unique_ip_count)
print("Unique ports:", unique_port_count)


#adding window n analysing it
port_windows = defaultdict(set)
ip_windows = defaultdict(set)
window_ports = defaultdict(set)
first_timestamp = float(packets[0].time)
'''
for packet in packets:
    if packet.haslayer("IP") and (
        packet.haslayer("TCP") or packet.haslayer("UDP")
    ):
        timestamp = float(packet.time)
        window = int((timestamp - first_timestamp) // 5)

        destination_ip = packet["IP"].dst
        if packet.haslayer("TCP"):
            destination_port = packet["TCP"].dport
        else:
            destination_port = packet["UDP"].dport

        port_windows[(window, destination_ip)].add(destination_port)
        ip_windows[window].add(destination_ip)
        window_ports[window].add(destination_port)
'''
print("\nUnique destination ports per 5-second window:")

sus_count = 0
non_suspicious_windows = 0

# this is only for debugging 

for (window, ip), ports in sorted(port_windows.items()):
    start = window * 5
    end = start + 5
    print(
        f"{start}-{end}s | IP: {ip} | Unique ports: {len(ports)} | "
        f"Window IPs: {len(ip_windows[window])} | "
        f"Window ports: {len(window_ports[window])}"
    )

#the actual check
if ip_windows:
    first_window = min(ip_windows)
    last_window = max(ip_windows)
    windows_to_check = range(first_window, last_window + 1)
else:
    windows_to_check = ()

for window in windows_to_check:
    is_suspicious_window = (
        len(ip_windows[window]) >= SUSPICIOUS_IP_THRESHOLD
        or len(window_ports[window]) >= SUSPICIOUS_PORT_THRESHOLD
    )

    if is_suspicious_window:
        sus_count += 1
        non_suspicious_windows = 0
    else:
        non_suspicious_windows += 1
        if non_suspicious_windows == 3:
            sus_count = max(0, sus_count - 1)
            non_suspicious_windows = 0

#confirm sus or na
confirmed_suspicious = sus_count >= 5
print("\nSuspicion score:", sus_count)
print("Confirmed suspicious:", "Yes" if confirmed_suspicious else "No")

