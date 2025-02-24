def generate_protocol_comparison_chart(self, plots_dir):
    """Generate a dedicated QUIC vs TCP vs UDP comparison chart"""
    print("Generating protocol comparison chart...")

    # Create data for chart
    app_names = list(self.results.keys())
    tcp_counts = []
    udp_counts = []
    quic_counts = []
    tls_counts = []

    for app in app_names:
        total_packets = len(self.results[app]['packet_sizes'])

        # Count TCP packets
        tcp_count = self.results[app]['protocols'].get(6, 0)
        tcp_counts.append(tcp_count)

        # Count UDP packets
        udp_count = self.results[app]['protocols'].get(17, 0)
        udp_counts.append(udp_count)

        # Count QUIC packets
        quic_count = self.results[app]['protocols'].get('QUIC', 0)
        quic_counts.append(quic_count)

        # Count TLS packets
        tls_count = len(self.results[app]['tls_headers'])
        tls_counts.append(tls_count)

    # Create stacked bar chart
    plt.figure(figsize=(12, 8))

    x = np.arange(len(app_names))
    width = 0.6

    # Stack the protocols
    plt.bar(x, tcp_counts, width, label='TCP', color='blue')
    plt.bar(x, udp_counts, width, bottom=tcp_counts, label='UDP', color='green')
    plt.bar(x, quic_counts, width, bottom=[t + u for t, u in zip(tcp_counts, udp_counts)],
            label='QUIC', color='purple')
    plt.bar(x, tls_counts, width, label='TLS', color='red', alpha=0.5)

    plt.xlabel('Application', fontsize=12)
    plt.ylabel('Packet Count', fontsize=12)
    plt.title('Protocol Usage Comparison', fontsize=14)
    plt.xticks(x, app_names, rotation=45)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.savefig(plots_dir / 'protocol_usage_comparison.png', dpi=300)
    plt.close()

    # Create percentage chart
    plt.figure(figsize=(12, 8))

    # Calculate percentages
    total_packets = [len(self.results[app]['packet_sizes']) for app in app_names]
    tcp_pct = [100 * t / tot if tot > 0 else 0 for t, tot in zip(tcp_counts, total_packets)]
    udp_pct = [100 * u / tot if tot > 0 else 0 for u, tot in zip(udp_counts, total_packets)]
    quic_pct = [100 * q / tot if tot > 0 else 0 for q, tot in zip(quic_counts, total_packets)]
    tls_pct = [100 * t / tot if tot > 0 else 0 for t, tot in zip(tls_counts, total_packets)]

    # Create a grouped bar chart
    x = np.arange(len(app_names))
    width = 0.2

    plt.bar(x - 1.5 * width, tcp_pct, width, label='TCP', color='blue')
    plt.bar(x - 0.5 * width, udp_pct, width, label='UDP', color='green')
    plt.bar(x + 0.5 * width, quic_pct, width, label='QUIC', color='purple')
    plt.bar(x + 1.5 * width, tls_pct, width, label='TLS', color='red')

    plt.xlabel('Application', fontsize=12)
    plt.ylabel('Percentage of Total Packets', fontsize=12)
    plt.title('Protocol Usage Percentages', fontsize=14)
    plt.xticks(x, app_names, rotation=45)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.savefig(plots_dir / 'protocol_percentage_chart.png', dpi=300)
    plt.close()
    from scapy.all import *


import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from collections import defaultdict
import numpy as np
from datetime import datetime
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.tls.record import TLS
from scapy.layers.http import HTTP
import logging
import warnings
import os


class TrafficAnalyzer:
    def __init__(self, pcap_dir):
        self.pcap_dir = pcap_dir
        self.results = {}
        self.app_names = []

        # הגדרת logging
        logging.basicConfig(level=logging.ERROR)
        # התעלמות מאזהרות
        warnings.filterwarnings("ignore")
        # השתקת אזהרות ספציפיות של scapy
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    def analyze_ip_header(self, ip_packet):
        """Extract IP header fields from packet"""
        return {
            'version': ip_packet.version,
            'ihl': ip_packet.ihl,
            'tos': ip_packet.tos,
            'len': ip_packet.len,
            'id': ip_packet.id,
            'flags': ip_packet.flags,
            'ttl': ip_packet.ttl,
            'proto': ip_packet.proto
        }

    def analyze_tcp_header(self, tcp_packet):
        """Extract TCP header fields from packet"""
        return {
            'sport': tcp_packet.sport,
            'dport': tcp_packet.dport,
            'seq': tcp_packet.seq,
            'ack': tcp_packet.ack,
            'window': tcp_packet.window,
            'flags': str(tcp_packet.flags)
        }

    def analyze_tls_header(self, packet):
        """Extract TLS header fields if present"""
        tls_info = {}
        try:
            if TLS in packet:
                tls = packet[TLS]
                # Extract available TLS fields
                if hasattr(tls, 'type'):
                    tls_info['type'] = tls.type
                if hasattr(tls, 'version'):
                    tls_info['version'] = tls.version
                if hasattr(tls, 'len'):
                    tls_info['len'] = tls.len
        except Exception:
            # Ignore TLS parsing errors
            pass
        return tls_info

    def analyze_pcap(self, pcap_file):
        """Analyze a single PCAP file"""
        print(f"Analyzing {pcap_file}...")
        try:
            packets = rdpcap(pcap_file)

            analysis = {
                'ip_headers': [],
                'tcp_headers': [],
                'tls_headers': [],
                'packet_sizes': [],
                'inter_arrival_times': [],
                'timestamps': [],
                'protocols': defaultdict(int),
                'ip_fields': {
                    'ttl': [],
                    'version': [],
                    'ihl': [],
                    'tos': [],
                    'len': [],
                    'id': [],
                    'flags': [],
                    'proto': []
                },
                'tcp_fields': {
                    'sport': [],
                    'dport': [],
                    'window': [],
                    'flags': defaultdict(int)
                },
                'tls_fields': {
                    'type': defaultdict(int),
                    'version': defaultdict(int)
                }
            }

            prev_time = None

            for packet in packets:
                try:
                    if IP not in packet:
                        continue

                    ip = packet[IP]
                    pkt_time = float(packet.time)
                    pkt_size = len(packet)

                    # Update times and sizes
                    analysis['packet_sizes'].append(pkt_size)
                    analysis['timestamps'].append(pkt_time)

                    if prev_time:
                        analysis['inter_arrival_times'].append(pkt_time - prev_time)
                    prev_time = pkt_time

                    # Analyze IP header
                    ip_info = self.analyze_ip_header(ip)
                    analysis['ip_headers'].append(ip_info)
                    analysis['protocols'][ip_info['proto']] += 1

                    # Store specific IP fields
                    for field, value in ip_info.items():
                        if field in analysis['ip_fields']:
                            analysis['ip_fields'][field].append(value)

                    # Analyze TCP if present
                    if TCP in packet:
                        tcp = packet[TCP]
                        tcp_info = self.analyze_tcp_header(tcp)
                        analysis['tcp_headers'].append(tcp_info)

                        # Store specific TCP fields
                        for field, value in tcp_info.items():
                            if field in analysis['tcp_fields'] and field != 'flags':
                                analysis['tcp_fields'][field].append(value)

                        # Count flag combinations
                        analysis['tcp_fields']['flags'][tcp_info['flags']] += 1

                    # Analyze UDP if present (for completeness)
                    if UDP in packet:
                        analysis['protocols']['UDP'] += 1
                        udp = packet[UDP]

                        # Check for QUIC protocol (UDP port 443)
                        if udp.dport == 443 or udp.sport == 443:
                            analysis['protocols']['QUIC'] += 1

                    # Analyze TLS if present
                    if TLS in packet:
                        tls_info = self.analyze_tls_header(packet)
                        if tls_info:
                            analysis['tls_headers'].append(tls_info)
                            analysis['protocols']['TLS'] += 1

                            # Store TLS fields
                            if 'type' in tls_info:
                                analysis['tls_fields']['type'][tls_info['type']] += 1
                            if 'version' in tls_info:
                                analysis['tls_fields']['version'][tls_info['version']] += 1

                except Exception as e:
                    print(f"Error processing packet: {str(e)}")
                    continue

            return analysis

        except Exception as e:
            print(f"Error reading file {pcap_file}: {str(e)}")
            return None

    def run_analysis(self):
        """Run analysis on all PCAP files in the directory"""
        pcap_files = list(Path(self.pcap_dir).glob('*.pcap*'))

        for pcap_file in pcap_files:
            app_name = pcap_file.stem
            self.app_names.append(app_name)
            analysis = self.analyze_pcap(str(pcap_file))
            if analysis:
                self.results[app_name] = analysis

        # Generate plots directory if it doesn't exist
        plots_dir = Path(self.pcap_dir) / 'plots'
        plots_dir.mkdir(exist_ok=True)

        # Generate all plots
        self.generate_ip_header_plots(plots_dir)
        self.generate_tcp_header_plots(plots_dir)
        self.generate_tls_header_plots(plots_dir)
        self.generate_packet_size_plots(plots_dir)
        self.generate_comparative_plots(plots_dir)

        # Generate specialized protocol comparison chart
        self.generate_protocol_comparison_chart(plots_dir)

    def generate_ip_header_plots(self, plots_dir):
        """Generate plots for IP header fields"""
        print("Generating IP header field plots...")

        # TTL Distribution
        self.create_comparison_boxplot(
            [self.results[app]['ip_fields']['ttl'] for app in self.results],
            self.results.keys(),
            'IP TTL Distribution',
            'TTL Value',
            plots_dir / 'ip_ttl_comparison.png'
        )

        # Protocol Distribution
        plt.figure(figsize=(12, 8))
        proto_data = {}

        # Convert protocol numbers to names
        proto_names = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}

        for app in self.results:
            proto_counts = defaultdict(int)
            for proto in self.results[app]['ip_fields']['proto']:
                proto_name = proto_names.get(proto, str(proto))
                proto_counts[proto_name] += 1
            proto_data[app] = proto_counts

        # Create bar chart
        apps = list(self.results.keys())
        all_protos = sorted(set().union(*[proto_data[app].keys() for app in apps]))

        x = np.arange(len(apps))
        width = 0.8 / len(all_protos)

        plt.figure(figsize=(14, 8))
        for i, proto in enumerate(all_protos):
            values = [proto_data[app].get(proto, 0) for app in apps]
            plt.bar(x + i * width, values, width, label=proto)

        plt.xlabel('Application')
        plt.ylabel('Packet Count')
        plt.title('IP Protocol Distribution')
        plt.xticks(x + width * len(all_protos) / 2 - width / 2, apps, rotation=45)
        plt.legend(title='Protocol')
        plt.tight_layout()
        plt.savefig(plots_dir / 'ip_protocol_distribution.png')
        plt.close()

        # IP Header Length (IHL) Distribution
        self.create_comparison_boxplot(
            [self.results[app]['ip_fields']['ihl'] for app in self.results],
            self.results.keys(),
            'IP Header Length Distribution',
            'IHL (32-bit words)',
            plots_dir / 'ip_ihl_comparison.png'
        )

    def generate_tcp_header_plots(self, plots_dir):
        """Generate plots for TCP header fields"""
        print("Generating TCP header field plots...")

        # TCP Window Size Distribution
        self.create_comparison_boxplot(
            [self.results[app]['tcp_fields']['window'] for app in self.results],
            self.results.keys(),
            'TCP Window Size Distribution',
            'Window Size',
            plots_dir / 'tcp_window_comparison.png'
        )

        # TCP Port Distribution (top 5 ports)
        plt.figure(figsize=(14, 8))
        for i, app in enumerate(self.results):
            ports = self.results[app]['tcp_fields']['dport']
            if not ports:
                continue

            # Count port frequencies
            port_counts = defaultdict(int)
            for port in ports:
                port_counts[port] += 1

            # Get top 5 ports
            top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]

            # Create subplot
            plt.subplot(len(self.results), 1, i + 1)
            top_port_names = [str(port) for port, _ in top_ports]
            top_port_counts = [count for _, count in top_ports]

            plt.barh(top_port_names, top_port_counts)
            plt.title(f'Top 5 Destination Ports for {app}')
            plt.xlabel('Packet Count')
            plt.ylabel('Port')

        plt.tight_layout()
        plt.savefig(plots_dir / 'tcp_dport_distribution.png')
        plt.close()

        # TCP Flags Distribution
        plt.figure(figsize=(14, 10))
        flag_data = {}

        for app in self.results:
            flag_data[app] = dict(self.results[app]['tcp_fields']['flags'])

        # Create bar chart
        apps = list(self.results.keys())
        all_flags = sorted(set().union(*[flag_data[app].keys() for app in apps]))

        x = np.arange(len(apps))
        width = 0.8 / len(all_flags) if all_flags else 0.8

        for i, flag in enumerate(all_flags):
            values = [flag_data[app].get(flag, 0) for app in apps]
            plt.bar(x + i * width, values, width, label=flag)

        plt.xlabel('Application')
        plt.ylabel('Packet Count')
        plt.title('TCP Flags Distribution')
        plt.xticks(x + width * len(all_flags) / 2 - width / 2, apps, rotation=45)
        plt.legend(title='Flags', loc='upper right')
        plt.tight_layout()
        plt.savefig(plots_dir / 'tcp_flags_distribution.png')
        plt.close()

    def generate_tls_header_plots(self, plots_dir):
        """Generate plots for TLS header fields"""
        print("Generating TLS header field plots...")

        # TLS Version Distribution
        plt.figure(figsize=(14, 8))
        version_data = {}

        # TLS version names
        tls_versions = {
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3'
        }

        for app in self.results:
            version_counts = defaultdict(int)
            for version, count in self.results[app]['tls_fields']['version'].items():
                version_name = tls_versions.get(version, f'Unknown (0x{version:04x})')
                version_counts[version_name] += count
            version_data[app] = version_counts

        # Create bar chart
        apps = list(self.results.keys())
        all_versions = sorted(set().union(*[version_data[app].keys() for app in apps]))

        x = np.arange(len(apps))
        width = 0.8 / len(all_versions) if all_versions else 0.8

        for i, version in enumerate(all_versions):
            values = [version_data[app].get(version, 0) for app in apps]
            plt.bar(x + i * width, values, width, label=version)

        plt.xlabel('Application')
        plt.ylabel('Packet Count')
        plt.title('TLS Version Distribution')
        plt.xticks(x + width * len(all_versions) / 2 - width / 2, apps, rotation=45)
        plt.legend(title='TLS Version')
        plt.tight_layout()
        plt.savefig(plots_dir / 'tls_version_distribution.png')
        plt.close()

        # TLS Type Distribution
        plt.figure(figsize=(14, 8))
        type_data = {}

        # TLS record type names
        tls_types = {
            20: 'Change Cipher Spec',
            21: 'Alert',
            22: 'Handshake',
            23: 'Application Data'
        }

        for app in self.results:
            type_counts = defaultdict(int)
            for type_val, count in self.results[app]['tls_fields']['type'].items():
                type_name = tls_types.get(type_val, f'Unknown ({type_val})')
                type_counts[type_name] += count
            type_data[app] = type_counts

        # Create bar chart
        all_types = sorted(set().union(*[type_data[app].keys() for app in apps]))

        x = np.arange(len(apps))
        width = 0.8 / len(all_types) if all_types else 0.8

        for i, type_name in enumerate(all_types):
            values = [type_data[app].get(type_name, 0) for app in apps]
            plt.bar(x + i * width, values, width, label=type_name)

        plt.xlabel('Application')
        plt.ylabel('Packet Count')
        plt.title('TLS Record Type Distribution')
        plt.xticks(x + width * len(all_types) / 2 - width / 2, apps, rotation=45)
        plt.legend(title='TLS Record Type')
        plt.tight_layout()
        plt.savefig(plots_dir / 'tls_type_distribution.png')
        plt.close()

        # TLS Usage Comparison (TLS vs non-TLS)
        plt.figure(figsize=(12, 8))

        tls_ratio = []
        for app in self.results:
            tls_count = len(self.results[app]['tls_headers'])
            total_count = len(self.results[app]['packet_sizes'])
            ratio = (tls_count / total_count) * 100 if total_count > 0 else 0
            tls_ratio.append(ratio)

        plt.bar(self.results.keys(), tls_ratio)
        plt.xlabel('Application')
        plt.ylabel('Percentage of TLS Packets')
        plt.title('TLS Usage Comparison')
        plt.ylim(0, 100)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(plots_dir / 'tls_usage_comparison.png')
        plt.close()

    def generate_packet_size_plots(self, plots_dir):
        """Generate plots for packet sizes"""
        print("Generating packet size plots...")

        # Packet Size Distribution
        plt.figure(figsize=(14, 10))

        for i, app in enumerate(self.results, 1):
            plt.subplot(len(self.results), 1, i)
            sns.histplot(self.results[app]['packet_sizes'], bins=50, kde=True)
            plt.title(f'Packet Size Distribution - {app}')
            plt.xlabel('Packet Size (bytes)')
            plt.ylabel('Count')

        plt.tight_layout()
        plt.savefig(plots_dir / 'packet_size_distributions.png')
        plt.close()

        # Packet Size Comparison
        self.create_comparison_boxplot(
            [self.results[app]['packet_sizes'] for app in self.results],
            self.results.keys(),
            'Packet Size Comparison',
            'Size (bytes)',
            plots_dir / 'packet_size_comparison.png'
        )

        # Packet Size Over Time
        plt.figure(figsize=(16, 12))

        for i, app in enumerate(self.results, 1):
            plt.subplot(len(self.results), 1, i)

            timestamps = np.array(self.results[app]['timestamps'])
            if len(timestamps) > 0:
                # Normalize to start at 0
                timestamps = timestamps - timestamps[0]

                plt.scatter(
                    timestamps,
                    self.results[app]['packet_sizes'],
                    s=10,  # smaller point size for better visibility
                    alpha=0.5  # transparency for overlapping points
                )
                plt.title(f'Packet Size Over Time - {app}')
                plt.xlabel('Time (seconds)')
                plt.ylabel('Packet Size (bytes)')

        plt.tight_layout()
        plt.savefig(plots_dir / 'packet_size_over_time.png')
        plt.close()

    def generate_comparative_plots(self, plots_dir):
        """Generate comprehensive comparison plots"""
        print("Generating comparative analysis plots...")

        # Create combined statistics dataframe
        stats = []
        for app in self.results:
            packet_sizes = self.results[app]['packet_sizes']
            inter_arrival = self.results[app]['inter_arrival_times']

            stats.append({
                'Application': app,
                'Total Packets': len(packet_sizes),
                'Avg Packet Size': np.mean(packet_sizes) if packet_sizes else 0,
                'Median Packet Size': np.median(packet_sizes) if packet_sizes else 0,
                'Std Dev Packet Size': np.std(packet_sizes) if packet_sizes else 0,
                'Avg Inter-arrival Time': np.mean(inter_arrival) * 1000 if inter_arrival else 0,  # to milliseconds
                'TCP %': (self.results[app]['protocols'][6] / len(packet_sizes) * 100) if packet_sizes else 0,
                'UDP %': (self.results[app]['protocols'][17] / len(packet_sizes) * 100) if packet_sizes else 0,
                'TLS %': (len(self.results[app]['tls_headers']) / len(packet_sizes) * 100) if packet_sizes else 0,
                'QUIC %': (self.results[app]['protocols']['QUIC'] / len(
                    packet_sizes) * 100) if packet_sizes and 'QUIC' in self.results[app]['protocols'] else 0
            })

        stats_df = pd.DataFrame(stats)

        # Create a comprehensive comparison chart
        plt.figure(figsize=(14, 10))

        # Plot key metrics
        metrics = ['Avg Packet Size', 'Median Packet Size', 'Avg Inter-arrival Time']

        for i, metric in enumerate(metrics, 1):
            plt.subplot(3, 1, i)
            plt.bar(stats_df['Application'], stats_df[metric])
            plt.title(f'Comparison of {metric}')
            plt.ylabel(metric)
            plt.xticks(rotation=45)

        plt.tight_layout()
        plt.savefig(plots_dir / 'comparative_statistics.png')
        plt.close()

        # Protocol distribution comparison
        plt.figure(figsize=(14, 8))

        # Create grouped bar chart for protocol percentages
        protocols = ['TCP %', 'UDP %', 'TLS %']
        x = np.arange(len(stats_df))
        width = 0.25

        for i, protocol in enumerate(protocols):
            plt.bar(x + (i - 1) * width, stats_df[protocol], width, label=protocol)

        plt.title('Protocol Distribution Comparison')
        plt.xlabel('Application')
        plt.ylabel('Percentage of Packets')
        plt.xticks(x, stats_df['Application'], rotation=45)
        plt.legend()
        plt.tight_layout()
        plt.savefig(plots_dir / 'protocol_percentage_comparison.png')
        plt.close()

        # Save summary statistics to CSV
        stats_df.to_csv(plots_dir / 'traffic_comparison_summary.csv', index=False)

        # Save detailed stats for analysis
        with open(plots_dir / 'detailed_stats.txt', 'w') as f:
            f.write("Traffic Analysis Summary\n")
            f.write("=======================\n\n")

            for app in self.results:
                f.write(f"\n{app} Analysis\n")
                f.write("-" * 30 + "\n")

                # Basic Statistics
                packet_sizes = self.results[app]['packet_sizes']
                total_packets = len(packet_sizes)
                total_bytes = sum(packet_sizes)

                f.write(f"Total Packets: {total_packets}\n")
                f.write(f"Total Data: {total_bytes / 1024 / 1024:.2f} MB\n")
                f.write(f"Average Packet Size: {np.mean(packet_sizes):.2f} bytes\n")

                # Protocol Distribution
                f.write("\nProtocol Distribution:\n")
                for proto, count in self.results[app]['protocols'].items():
                    proto_name = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
                    f.write(f"  {proto_name}: {count} packets ({count / total_packets * 100:.2f}%)\n")

                # Flag Distribution for TCP
                if self.results[app]['tcp_fields']['flags']:
                    f.write("\nTCP Flag Distribution:\n")
                    for flag, count in sorted(self.results[app]['tcp_fields']['flags'].items(),
                                              key=lambda x: x[1], reverse=True):
                        f.write(f"  {flag}: {count} packets\n")

                # TLS Information
                tls_count = len(self.results[app]['tls_headers'])
                if tls_count > 0:
                    f.write(f"\nTLS Usage: {tls_count} packets ({tls_count / total_packets * 100:.2f}%)\n")

                    # TLS Version Distribution
                    if self.results[app]['tls_fields']['version']:
                        f.write("\nTLS Version Distribution:\n")
                        for version, count in sorted(self.results[app]['tls_fields']['version'].items()):
                            version_name = {
                                0x0301: 'TLS 1.0',
                                0x0302: 'TLS 1.1',
                                0x0303: 'TLS 1.2',
                                0x0304: 'TLS 1.3'
                            }.get(version, f'Unknown (0x{version:04x})')
                            f.write(f"  {version_name}: {count} packets\n")

                f.write("\n" + "=" * 50 + "\n")

    def create_comparison_boxplot(self, data_list, labels, title, ylabel, save_path):
        """Helper to create boxplot comparisons"""
        plt.figure(figsize=(12, 8))

        # Filter out empty datasets
        valid_data = []
        valid_labels = []
        for d, label in zip(data_list, labels):
            if d and len(d) > 0:  # Check if the data list is not empty
                valid_data.append(d)
                valid_labels.append(label)

        if not valid_data:
            print(f"Warning: No valid data for {title}")
            return

        # Create boxplot
        bp = plt.boxplot(valid_data, labels=valid_labels, patch_artist=True)

        # Change colors to make boxplots more visible
        for box in bp['boxes']:
            box.set(color='blue', linewidth=2)
            box.set(facecolor='lightblue')
        for whisker in bp['whiskers']:
            whisker.set(color='blue', linewidth=2)
        for cap in bp['caps']:
            cap.set(color='blue', linewidth=2)
        for median in bp['medians']:
            median.set(color='red', linewidth=2)
        for flier in bp['fliers']:
            flier.set(marker='o', color='black', alpha=0.7)

        plt.title(title, fontsize=14)
        plt.ylabel(ylabel, fontsize=12)
        plt.xlabel('Application', fontsize=12)
        plt.xticks(rotation=45, fontsize=10)
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(save_path, dpi=300)  # Higher resolution
        plt.close()


def main():
    # Use user-specified path or current directory
    pcap_dir = input("Enter the directory path containing PCAP files (or press Enter to use current directory): ")

    if not pcap_dir:
        pcap_dir = os.getcwd()

    analyzer = TrafficAnalyzer(pcap_dir)
    analyzer.run_analysis()

    print("Analysis complete! Check the 'plots' directory for visualizations.")


if __name__ == "__main__":
    main()