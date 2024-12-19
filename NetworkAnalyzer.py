#!/usr/bin/env python3

import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, DNS, conf, wrpcap
from datetime import datetime
import threading
from collections import defaultdict
from colorama import Fore, Style, init
import os
import signal
import sys
import netifaces

# Initialize colorama
init()

# Default PCAP file for saving packets
PCAP_FILE = "captured_traffic.pcap"

def get_default_interface():
    """Get the default network interface."""
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][1]
    except:
        pass

    # Fallback to first available interface
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        if iface != 'lo':  # Skip loopback
            return iface
    return None


class PacketAnalyzer:
    def __init__(self, interface=None, verbose=False, log_file=PCAP_FILE):
        self.interface = interface
        self.verbose = verbose
        self.packet_count = 0
        self.start_time = datetime.now()
        self.running = True
        self.stats = defaultdict(int)
        self.connections = defaultdict(int)
        self.recent_packets = []
        self.max_recent_packets = 10
        self.log_file = log_file
        self.packets = []
        signal.signal(signal.SIGINT, self.handle_interrupt)

    def handle_interrupt(self, signum, frame):
        """Handle Ctrl+C by printing statistics and saving packets."""
        self.running = False
        self.print_final_statistics()
        self.save_to_pcap()
        sys.exit(0)

    def update_statistics(self, packet):
        """Update packet statistics."""
        self.packet_count += 1
        if IP in packet:
            self.stats['IP'] += 1
            if TCP in packet:
                self.stats['TCP'] += 1
                conn = f"{packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}"
                self.connections[conn] += 1
            elif UDP in packet:
                self.stats['UDP'] += 1
            elif ICMP in packet:
                self.stats['ICMP'] += 1
        elif ARP in packet:
            self.stats['ARP'] += 1

    def save_to_pcap(self):
        """Save captured packets to a PCAP file."""
        if self.packets:
            print(f"{Fore.CYAN}Saving captured packets to {self.log_file}...{Style.RESET_ALL}")
            wrpcap(self.log_file, self.packets)
            print(f"{Fore.GREEN}Packets saved successfully!{Style.RESET_ALL}")

    def print_live_statistics(self):
        """Print live statistics."""
        while self.running:
            try:
                os.system("cls" if os.name == "nt" else "clear")
                duration = (datetime.now() - self.start_time).total_seconds()
                pps = self.packet_count / duration if duration > 0 else 0

                print(f"{Fore.CYAN}=== Live Packet Capture Statistics ==={Style.RESET_ALL}")
                print(f"Interface: {self.interface}")
                print(f"Duration: {duration:.2f} seconds")
                print(f"Total Packets: {self.packet_count}")
                print(f"Packets/sec: {pps:.2f}")
                print("\nProtocol Distribution:")
                for proto, count in self.stats.items():
                    print(f"{proto}: {count}")
                print("\nTop Connections:")
                for conn, count in sorted(self.connections.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"{conn}: {count} packets")
                print("\nRecent Packets:")
                for packet in self.recent_packets[-10:]:
                    print(packet)
                print("\nPress Ctrl+C to stop capturing...")
                threading.Event().wait(1)
            except Exception:
                pass

    def process_packet(self, packet):
        """Process and log each captured packet."""
        self.update_statistics(packet)
        self.packets.append(packet)
        if len(self.packets) > 10000:  # Prevent memory overload
            self.save_to_pcap()
            self.packets = []

        try:
            src_ip = packet[IP].src if IP in packet else "N/A"
            dst_ip = packet[IP].dst if IP in packet else "N/A"
            proto = packet.getlayer(IP).proto if IP in packet else "N/A"
            info = f"{src_ip} -> {dst_ip} (Proto: {proto})"
            with threading.Lock():
                self.recent_packets.append(info)
                if len(self.recent_packets) > self.max_recent_packets:
                    self.recent_packets.pop(0)
        except Exception as e:
            if self.verbose:
                print(f"Error processing packet: {e}")

    def print_final_statistics(self):
        """Print final statistics when stopping."""
        duration = (datetime.now() - self.start_time).total_seconds()
        pps = self.packet_count / duration if duration > 0 else 0

        print(f"\n{Fore.CYAN}=== Final Packet Capture Statistics ==={Style.RESET_ALL}")
        print(f"Interface: {self.interface}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total Packets: {self.packet_count}")
        print(f"Packets/sec: {pps:.2f}")
        print("\nProtocol Distribution:")
        for proto, count in self.stats.items():
            print(f"{proto}: {count}")
        print("\nTop Connections:")
        for conn, count in sorted(self.connections.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"{conn}: {count} packets")


def main():
    parser = argparse.ArgumentParser(description="Advanced Network Packet Analyzer")
    parser.add_argument("-i", "--interface", help="Specify network interface to capture from")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80')", default="")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", help="Output PCAP file", default=PCAP_FILE)

    args = parser.parse_args()

    interface = args.interface or get_default_interface()
    if not interface:
        print(f"{Fore.RED}Error: No network interface found!{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.CYAN}Starting packet capture on interface {interface}...{Style.RESET_ALL}")
    analyzer = PacketAnalyzer(interface, args.verbose, args.output)

    # Start live statistics thread
    stats_thread = threading.Thread(target=analyzer.print_live_statistics)
    stats_thread.daemon = True
    stats_thread.start()

    try:
        sniff(iface=interface, filter=args.filter, prn=analyzer.process_packet, store=False)
    except Exception as e:
        print(f"{Fore.RED}Error during packet capture: {e}{Style.RESET_ALL}")
    finally:
        analyzer.running = False
        stats_thread.join(timeout=1)
        analyzer.save_to_pcap()


if __name__ == "__main__":
    main()
