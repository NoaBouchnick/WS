#!/usr/bin/env python3
"""
Network Traffic Analyzer
------------------------
Analyzes PCAP files to compare network traffic characteristics of different applications:
- Web browsers (Chrome, Edge)
- Audio streaming (Spotify)
- Video streaming (YouTube)
- Video conferencing (Zoom)

Required packages:
- scapy
- pandas
- matplotlib
- seaborn
- numpy
"""

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import numpy as np
import os
from collections import defaultdict

# Setup visualization style
plt.style.use('ggplot')
sns.set_palette("tab10")


class TrafficAnalyzer:
    def __init__(self, pcap_dir):
        self.pcap_dir = pcap_dir
        self.results = {}

    def analyze_pcaps(self):
        """Analyze all PCAP files in directory"""
        pcap_files = []
        for ext in ['*.pcap', '*.pcapng']:
            pcap_files.extend(list(Path(self.pcap_dir).glob(ext)))

        if not pcap_files:
            print(f"No PCAP files found in {self.pcap_dir}")
            return False

        for pcap_file in pcap_files:
            app_name = pcap_file.stem
            print(f"Analyzing {app_name}...")

            try:
                # Read packets and extract data
                packets = rdpcap(str(pcap_file))
                data = self._extract_features(packets)
                self.results[app_name] = data
            except Exception as e:
                print(f"Error analyzing {app_name}: {e}")

        return bool(self.results)

    def _extract_features(self, packets):
        """Extract features from packet list, focusing on requirements A, B, C, D"""
        data = {
            # D. Packet sizes
            'packet_size': [],

            # A. IP header fields
            'ip': {
                'ttl': [],
                'ihl': [],
                'tos': [],
                'flags': defaultdict(int)
            },

            # B. TCP header fields
            'tcp': {
                'window_size': [],
                'flags': defaultdict(int),
                'options': defaultdict(int)
            },

            # C. TLS header fields (limited without decryption)
            'tls': {
                'count': 0
            },

            # Extra useful information
            'protocols': {'TCP': 0, 'UDP': 0, 'TLS': 0, 'QUIC': 0},
            'direction': {'in': 0, 'out': 0},
            'inter_arrival': []
        }

        prev_time = None

        for pkt in packets:
            if IP not in pkt:
                continue

            # Basic IP features - A. IP header fields
            ip = pkt[IP]
            time = float(pkt.time)
            size = len(pkt)

            # D. Packet sizes
            data['packet_size'].append(size)

            # A. IP header fields
            data['ip']['ttl'].append(ip.ttl)
            data['ip']['ihl'].append(ip.ihl)
            data['ip']['tos'].append(ip.tos)

            # IP flags
            flag_str = str(ip.flags) if hasattr(ip, 'flags') else 'None'
            data['ip']['flags'][flag_str] += 1

            # Traffic direction
            if ip.src.startswith(('192.168.', '10.', '172.')):
                data['direction']['out'] += 1
            else:
                data['direction']['in'] += 1

            # Inter-arrival time
            if prev_time:
                data['inter_arrival'].append(time - prev_time)
            prev_time = time

            # Protocol counting
            if ip.proto == 6:  # TCP
                data['protocols']['TCP'] += 1

                # B. TCP header fields
                if TCP in pkt:
                    tcp = pkt[TCP]
                    data['tcp']['window_size'].append(tcp.window)

                    # TCP flags
                    flags = []
                    if tcp.flags.S: flags.append("SYN")
                    if tcp.flags.A: flags.append("ACK")
                    if tcp.flags.F: flags.append("FIN")
                    if tcp.flags.P: flags.append("PSH")
                    if tcp.flags.R: flags.append("RST")

                    flag_str = " ".join(flags)
                    if flag_str:
                        data['tcp']['flags'][flag_str] += 1

                    # TCP options
                    if tcp.options:
                        for opt in tcp.options:
                            opt_name = opt[0] if isinstance(opt, tuple) else opt
                            data['tcp']['options'][str(opt_name)] += 1

                    # C. TLS detection (simplified approach)
                    if tcp.dport == 443 or tcp.sport == 443:
                        data['protocols']['TLS'] += 1
                        data['tls']['count'] += 1

            elif ip.proto == 17:  # UDP
                data['protocols']['UDP'] += 1

                # QUIC detection (modern HTTP/3)
                if UDP in pkt:
                    udp = pkt[UDP]
                    if (udp.dport == 443 or udp.sport == 443) and size > 40:
                        data['protocols']['QUIC'] += 1

        return data

    def create_visualizations(self):
        """Generate all visualizations that meet the requirements"""
        plots_dir = Path(self.pcap_dir) / 'plots'
        plots_dir.mkdir(exist_ok=True)

        print("Generating visualizations...")

        # Create summary dataframe
        summary_df = self._create_summary()
        summary_df.to_csv(plots_dir / 'summary.csv')

        # A. IP header fields plots (improved versions)
        self._plot_ip_ttl_values(plots_dir)
        self._plot_ip_header_length(plots_dir)

        # B. TCP header fields plots
        self._plot_tcp_window_size(plots_dir)
        self._plot_tcp_flags(plots_dir)

        # C. TLS information
        self._plot_tls_usage(plots_dir)

        # D. Packet size plots (improved version)
        self._plot_packet_sizes(plots_dir)

        # Additional useful plots
        self._plot_protocols(plots_dir)
        self._plot_traffic_direction(plots_dir)

        print(f"Analysis complete! Results saved to {plots_dir}")

    def _create_summary(self):
        """Create summary statistics dataframe"""
        data = []

        for app, features in self.results.items():
            total = len(features['packet_size'])
            if not total:
                continue

            # Calculate summary stats
            row = {
                'Application': app,
                'Total Packets': total,
                'Avg Packet Size (bytes)': np.mean(features['packet_size']),
                'Median Packet Size (bytes)': np.median(features['packet_size']),
                'IP Header Size (bytes)': np.mean(features['ip']['ihl']) * 4 if features['ip']['ihl'] else 0,
                'Avg TTL': np.mean(features['ip']['ttl']) if features['ip']['ttl'] else 0,
                'TCP Window Size': np.mean(features['tcp']['window_size']) if features['tcp']['window_size'] else 0,
                'TCP %': features['protocols']['TCP'] / total * 100,
                'UDP %': features['protocols']['UDP'] / total * 100,
                'TLS %': features['protocols']['TLS'] / total * 100,
                'QUIC %': features['protocols']['QUIC'] / total * 100,
                'In %': features['direction']['in'] / total * 100,
                'Out %': features['direction']['out'] / total * 100,
            }

            # Add timing if available
            if features['inter_arrival']:
                row['Avg Inter-arrival (ms)'] = np.mean(features['inter_arrival']) * 1000

            data.append(row)

        return pd.DataFrame(data)

    def _plot_ip_ttl_values(self, plots_dir):
        """Plot IP TTL values (improved version)"""
        ttl_data = []

        for app, features in self.results.items():
            ttl_values = features['ip']['ttl']
            if not ttl_values:
                continue

            # Find most common TTL
            values, counts = np.unique(ttl_values, return_counts=True)
            most_common_idx = np.argmax(counts)
            most_common = values[most_common_idx]
            percentage = (counts[most_common_idx] / len(ttl_values)) * 100

            ttl_data.append({
                'Application': app,
                'Most Common TTL': most_common,
                'Percentage': percentage
            })

        if not ttl_data:
            return

        # Create DataFrame
        df = pd.DataFrame(ttl_data)

        plt.figure(figsize=(12, 7))

        # Simple bar chart for most common TTL
        bars = plt.bar(df['Application'], df['Most Common TTL'], color='lightgreen')

        # Add percentage labels
        for i, (_, row) in enumerate(df.iterrows()):
            plt.text(i, row['Most Common TTL'] + 1,
                     f"TTL: {row['Most Common TTL']:.0f}\n({row['Percentage']:.1f}%)",
                     ha='center')

        plt.title('Most Common TTL Values by Application')
        plt.ylabel('TTL Value')
        plt.grid(axis='y', alpha=0.3)
        plt.xticks(rotation=30, ha='right')
        plt.tight_layout()

        plt.savefig(plots_dir / 'ip_ttl_values.png', dpi=300)
        plt.close()

    def _plot_ip_header_length(self, plots_dir):
        """Plot IP Header Length (improved version)"""
        # Collect average IHL values for each application
        avg_ihl_data = []

        for app, features in self.results.items():
            ihl_values = features['ip']['ihl']
            if not ihl_values:
                continue

            # Calculate the average IHL and convert to bytes
            avg_ihl = np.mean(ihl_values)
            byte_size = avg_ihl * 4  # IHL is in 4-byte units

            # Calculate the percentage of standard IHL (5)
            values, counts = np.unique(ihl_values, return_counts=True)
            percentages = {}
            for val, count in zip(values, counts):
                percentages[val] = (count / len(ihl_values)) * 100

            # Get percentage of standard IHL=5 (if present)
            std_pct = percentages.get(5.0, 0)

            avg_ihl_data.append({
                'Application': app,
                'Average IHL': avg_ihl,
                'Header Size (bytes)': byte_size,
                'Standard IHL %': std_pct
            })

        if not avg_ihl_data:
            return

        # Create DataFrame for the averages
        avg_df = pd.DataFrame(avg_ihl_data)

        # Plot simple bar chart with average values
        plt.figure(figsize=(12, 7))

        bars = plt.bar(avg_df['Application'], avg_df['Header Size (bytes)'], color='lightblue')

        # Add information labels with more detail
        for i, row in avg_df.iterrows():
            plt.text(i, row['Header Size (bytes)'] + 0.3,
                     f"Avg IHL: {row['Average IHL']:.2f}\n({row['Standard IHL %']:.1f}% standard)",
                     ha='center', va='bottom', fontsize=9)

        plt.title('IP Header Length by Application', fontsize=14)
        plt.ylabel('Header Size (bytes)', fontsize=12)
        plt.xticks(rotation=30, ha='right')
        plt.grid(axis='y', alpha=0.3)

        # Add explanation of IHL
        plt.figtext(0.5, 0.01,
                    "Standard IP header (IHL=5) is 20 bytes. Higher values indicate use of IP options.",
                    ha='center', fontsize=10,
                    bbox=dict(boxstyle='round,pad=0.5', facecolor='white', alpha=0.8))

        plt.tight_layout(rect=[0, 0.05, 1, 0.95])  # Make room for the explanation
        plt.savefig(plots_dir / 'ip_header_length.png', dpi=300)
        plt.close()

    def _plot_tcp_window_size(self, plots_dir):
        """Plot TCP Window Size (improved version)"""
        window_data = []

        for app, features in self.results.items():
            win_sizes = features['tcp']['window_size']
            if not win_sizes or len(win_sizes) < 10:
                continue

            window_data.append({
                'Application': app,
                'Mean Window Size': np.mean(win_sizes)
            })

        if not window_data:
            return

        # Create DataFrame
        df = pd.DataFrame(window_data)

        # Sort by window size
        df = df.sort_values('Mean Window Size', ascending=False)

        plt.figure(figsize=(12, 7))

        # Simple bar chart
        bars = plt.bar(df['Application'], df['Mean Window Size'], color='skyblue')

        # Add formatted value labels
        for i, v in enumerate(df['Mean Window Size']):
            if v < 1000:
                formatted = f"{v:.0f}"
            elif v < 1000000:
                formatted = f"{v / 1000:.1f}K"
            else:
                formatted = f"{v / 1000000:.1f}M"

            plt.text(i, v * 1.02, formatted, ha='center')

        plt.title('Average TCP Window Size by Application')
        plt.ylabel('Window Size (bytes)')
        plt.grid(axis='y', alpha=0.3)
        plt.xticks(rotation=30, ha='right')
        plt.tight_layout()

        plt.savefig(plots_dir / 'tcp_window_size.png', dpi=300)
        plt.close()

    def _plot_tcp_flags(self, plots_dir):
        """Plot TCP Flags Distribution"""
        tcp_flags_data = []
        for app, features in self.results.items():
            if not features['tcp']['flags']:
                continue

            total_tcp = features['protocols']['TCP']
            if total_tcp == 0:
                continue

            # Get top flags
            top_flags = sorted(features['tcp']['flags'].items(),
                               key=lambda x: x[1], reverse=True)[:3]

            for flag, count in top_flags:
                tcp_flags_data.append({
                    'Application': app,
                    'TCP Flag': flag,
                    'Percentage': count / total_tcp * 100
                })

        if tcp_flags_data:
            df = pd.DataFrame(tcp_flags_data)

            plt.figure(figsize=(12, 8))
            ax = sns.barplot(data=df, x='Percentage', y='TCP Flag', hue='Application')

            plt.title('TCP Flags Distribution by Application')
            plt.xlabel('Percentage of TCP Packets (%)')
            plt.grid(axis='x', linestyle='--', alpha=0.5)
            plt.tight_layout()
            plt.savefig(plots_dir / 'tcp_flags.png', dpi=300)
            plt.close()

    def _plot_tls_usage(self, plots_dir):
        """Plot TLS usage information"""
        tls_data = []
        for app, features in self.results.items():
            total = len(features['packet_size'])
            if not total:
                continue

            tls_percentage = features['protocols']['TLS'] / total * 100
            tls_data.append({
                'Application': app,
                'TLS %': tls_percentage
            })

        if tls_data:
            df = pd.DataFrame(tls_data)
            plt.figure(figsize=(10, 6))

            ax = sns.barplot(data=df, x='Application', y='TLS %')

            # Add percentage labels
            for i, row in df.iterrows():
                ax.text(i, row['TLS %'] + 1, f"{row['TLS %']:.1f}%", ha='center')

            plt.title('TLS Usage by Application')
            plt.ylabel('Percentage of TLS Packets (%)')
            plt.xlabel('Application')
            plt.xticks(rotation=30, ha='right')
            plt.grid(axis='y', linestyle='--', alpha=0.5)
            plt.tight_layout()
            plt.savefig(plots_dir / 'tls_usage.png', dpi=300)
            plt.close()

    def _plot_packet_sizes(self, plots_dir):
        """Plot packet size distributions (improved version)"""
        # First make a boxplot comparison
        size_data = []
        for app, features in self.results.items():
            # Skip if not enough data
            if not features['packet_size'] or len(features['packet_size']) < 10:
                continue

            # Create rows for DataFrame
            for size in features['packet_size']:
                size_data.append({
                    'Application': app,
                    'Packet Size': size
                })

        if size_data:
            df = pd.DataFrame(size_data)

            plt.figure(figsize=(10, 6))
            ax = sns.boxplot(data=df, x='Application', y='Packet Size', showfliers=False)

            # Add mean markers
            for i, app in enumerate(df['Application'].unique()):
                app_sizes = df[df['Application'] == app]['Packet Size']
                mean_val = app_sizes.mean()

                plt.scatter(i, mean_val, marker='o', color='red', s=40, zorder=3)
                plt.text(i, mean_val, f'μ={mean_val:.0f}', ha='center', va='bottom')

            plt.title('Packet Size Comparison by Application')
            plt.ylabel('Packet Size (bytes)')
            plt.xlabel('Application')
            plt.xticks(rotation=30, ha='right')
            plt.grid(axis='y', linestyle='--', alpha=0.5)
            plt.tight_layout()
            plt.savefig(plots_dir / 'packet_size_boxplot.png', dpi=300)
            plt.close()

        # Then make separate distribution plots for each app
        for app, features in self.results.items():
            packet_sizes = np.array(features['packet_size'])
            if len(packet_sizes) < 10:
                continue

            # Remove extreme outliers
            packet_sizes = packet_sizes[packet_sizes < np.percentile(packet_sizes, 99)]

            plt.figure(figsize=(10, 6))
            sns.histplot(packet_sizes, kde=True, bins=20)

            plt.title(f'Packet Size Distribution - {app}')
            plt.xlabel('Packet Size (bytes)')
            plt.ylabel('Frequency')
            plt.grid(True, alpha=0.3)
            plt.tight_layout()

            # Save each app to a separate file
            plt.savefig(plots_dir / f'packet_size_dist_{app}.png', dpi=300)
            plt.close()

    def _plot_protocols(self, plots_dir):
        """Plot protocol distribution"""
        data = []
        for app, features in self.results.items():
            total = len(features['packet_size'])
            if not total:
                continue

            row = {'Application': app}
            for proto in ['TCP', 'UDP', 'TLS', 'QUIC']:
                row[proto] = features['protocols'][proto] / total * 100
            data.append(row)

        if data:
            df = pd.DataFrame(data)
            df.set_index('Application', inplace=True)

            plt.figure(figsize=(10, 6))
            ax = df.plot(kind='bar', figsize=(10, 6), width=0.7)

            # Add percentage labels
            for container in ax.containers:
                ax.bar_label(container, fmt='%.1f%%')

            plt.title('Protocol Distribution by Application')
            plt.ylabel('Percentage of Packets (%)')
            plt.legend(title='Protocol')
            plt.grid(axis='y', linestyle='--', alpha=0.5)
            plt.xticks(rotation=30, ha='right')
            plt.tight_layout()
            plt.savefig(plots_dir / 'protocol_distribution.png', dpi=300)
            plt.close()

    def _plot_traffic_direction(self, plots_dir):
        """Plot traffic direction (incoming vs outgoing)"""
        data = []
        for app, features in self.results.items():
            total = features['direction']['in'] + features['direction']['out']
            if not total:
                continue

            in_pct = features['direction']['in'] / total * 100
            out_pct = features['direction']['out'] / total * 100

            data.append({
                'Application': app,
                'Incoming': in_pct,
                'Outgoing': out_pct
            })

        if data:
            df = pd.DataFrame(data)
            plt.figure(figsize=(10, 6))
            ax = df.plot(x='Application', y=['Incoming', 'Outgoing'], kind='bar', stacked=True, width=0.7)

            # Add percentage labels
            for container in ax.containers:
                ax.bar_label(container, fmt='%.1f%%')

            plt.title('Traffic Direction by Application')
            plt.ylabel('Percentage of Packets (%)')
            plt.legend(title='Direction')
            plt.grid(axis='y', linestyle='--', alpha=0.5)
            plt.xticks(rotation=30, ha='right')
            plt.tight_layout()
            plt.savefig(plots_dir / 'traffic_direction.png', dpi=300)
            plt.close()


def main():
    """Main entry point"""
    pcap_dir = input("Enter path to PCAP directory (or press Enter for current directory): ")
    if not pcap_dir:
        pcap_dir = os.getcwd()

    analyzer = TrafficAnalyzer(pcap_dir)
    if analyzer.analyze_pcaps():
        analyzer.create_visualizations()
    else:
        print("No valid data to analyze")


if __name__ == "__main__":
    main()