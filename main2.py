import argparse
from collections import Counter, defaultdict

from scapy.all import rdpcap


WINDOW_SECONDS = 5
SUSPICIOUS_PORT_THRESHOLD = 50
SUSPICIOUS_IP_THRESHOLD = 5
SUSPICIOUS_WINDOW_SCORE = 5


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze inbound traffic to a server from a saved PCAP."
    )
    parser.add_argument(
        "capture",
        nargs="?",
        default="captures/nmap_standard_scan",
        help="Path to the PCAP file (default: captures/nmap_standard_scan)",
    )
    parser.add_argument(
        "--server-ip",
        help=(
            "Only inspect traffic addressed to this server IP. If omitted, "
            "each destination IP is analyzed as its own server."
        ),
    )
    return parser.parse_args()


def get_transport_port(packet):
    if packet.haslayer("TCP"):
        return packet["TCP"].dport
    if packet.haslayer("UDP"):
        return packet["UDP"].dport
    return None


def main() -> None:
    args = parse_args()
    packets = rdpcap(args.capture)
    print("Packets captured:", len(packets))

    if not packets:
        print("No packets to analyze.")
        return

    protocol_counts = Counter()
    unique_senders = set()
    unique_server_ports = set()

    # (window, sender IP, server IP) -> destination ports contacted
    sender_port_windows = defaultdict(set)
    window_sender_ips = defaultdict(set)
    window_ports = defaultdict(set)

    first_timestamp = float(packets[0].time)

    for packet in packets:
        if not packet.haslayer("IP"):
            continue

        server_ip = packet["IP"].dst
        if args.server_ip and server_ip != args.server_ip:
            continue

        destination_port = get_transport_port(packet)
        if destination_port is None:
            protocol_counts["ICMP" if packet.haslayer("ICMP") else "Other"] += 1
            continue

        if packet.haslayer("TCP"):
            protocol_counts["TCP"] += 1
        else:
            protocol_counts["UDP"] += 1

        sender_ip = packet["IP"].src
        unique_senders.add(sender_ip)
        unique_server_ports.add(destination_port)

        timestamp = float(packet.time)
        window = int((timestamp - first_timestamp) // WINDOW_SECONDS)
        sender_key = (window, sender_ip, server_ip)

        sender_port_windows[sender_key].add(destination_port)
        window_sender_ips[window].add(sender_ip)
        window_ports[window].add(destination_port)

    print("\nInbound packet counts by protocol:")
    for protocol, count in protocol_counts.items():
        print(protocol, ":", count)

    print("\nUnique inbound network entities:")
    print("Unique senders:", len(unique_senders))
    print("Unique server ports:", len(unique_server_ports))

    print("\nUnique destination ports per sender in each 5-second window:")
    '''for (window, sender_ip, server_ip), ports in sorted(sender_port_windows.items()):
        start = window * WINDOW_SECONDS
        end = start + WINDOW_SECONDS
        print(
            f"{start}-{end}s | Sender: {sender_ip} | Server: {server_ip} | "
            f"Unique ports: {len(ports)} | "
            f"Window senders: {len(window_sender_ips[window])} | "
            f"Window ports: {len(window_ports[window])}"
        )'''

    if not window_sender_ips:
        print("\nSuspicion score: 0")
        print("Confirmed suspicious: No")
        return

    first_window = min(window_sender_ips)
    last_window = max(window_sender_ips)
    suspicion_score = 0
    quiet_windows = 0

    for window in range(first_window, last_window + 1):
        suspicious_sources = [
            (sender_ip, server_ip, ports)
            for (source_window, sender_ip, server_ip), ports in sender_port_windows.items()
            if source_window == window
            and len(ports) >= SUSPICIOUS_PORT_THRESHOLD
        ]

        is_suspicious_window = bool(suspicious_sources) or (
            len(window_sender_ips[window]) >= SUSPICIOUS_IP_THRESHOLD
            and len(window_ports[window]) >= SUSPICIOUS_PORT_THRESHOLD
        )

        if is_suspicious_window:
            suspicion_score += 1
            quiet_windows = 0
            '''for sender_ip, server_ip, ports in suspicious_sources:
                print(
                    f"ALERT {window * WINDOW_SECONDS}-"
                    f"{(window + 1) * WINDOW_SECONDS}s | "
                    f"Sender {sender_ip} contacted {len(ports)} ports on "
                    f"{server_ip}"
                )'''
        else:
            quiet_windows += 1
            if quiet_windows == 3:
                suspicion_score = max(0, suspicion_score - 1)
                quiet_windows = 0

    print("\nSuspicion score:", suspicion_score)
    print(
        "Confirmed suspicious:",
        "Yes" if suspicion_score >= SUSPICIOUS_WINDOW_SCORE else "No",
    )


if __name__ == "__main__":
    main()
