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
                'flags': defaultdict(int),
                'src': defaultdict(int),  # New field to track source IP addresses
                'dst': defaultdict(int)  # New field to track destination IP addresses
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

            # Track IP addresses
            data['ip']['src'][ip.src] += 1
            data['ip']['dst'][ip.dst] += 1

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
        self._plot_ip_ttl_and_addresses(plots_dir)  # Changed function name

        # B. TCP header fields plots
        self._plot_tcp_window_size(plots_dir)

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

    def _plot_ip_ttl_and_addresses(self, plots_dir):
        """Plot IP TTL values and most common IP addresses"""
        ip_data = []

        for app, features in self.results.items():
            ttl_values = features['ip']['ttl']
            src_addresses = features['ip']['src']
            dst_addresses = features['ip']['dst']

            if not ttl_values:
                continue

            # Calculate TTL statistics
            ttl_values_unique, ttl_counts = np.unique(ttl_values, return_counts=True)
            most_common_idx = np.argmax(ttl_counts)
            most_common_ttl = ttl_values_unique[most_common_idx]
            ttl_percentage = (ttl_counts[most_common_idx] / len(ttl_values)) * 100

            # Get top source and destination addresses
            top_src = sorted(src_addresses.items(), key=lambda x: x[1], reverse=True)[:3]
            top_dst = sorted(dst_addresses.items(), key=lambda x: x[1], reverse=True)[:3]

            # Calculate percentages
            total_packets = len(ttl_values)
            top_src_with_pct = [(ip, count, count / total_packets * 100) for ip, count in top_src]
            top_dst_with_pct = [(ip, count, count / total_packets * 100) for ip, count in top_dst]

            ip_data.append({
                'Application': app,
                'Most Common TTL': most_common_ttl,
                'TTL Percentage': ttl_percentage,
                'Top Source IPs': top_src_with_pct,
                'Top Destination IPs': top_dst_with_pct,
                'Total Packets': total_packets
            })

        if not ip_data:
            return

        # Create DataFrame
        df = pd.DataFrame(ip_data)

        # Create a figure with two subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

        # First subplot: TTL values - SIMPLIFIED with uniform color
        apps = df['Application'].values
        x = np.arange(len(apps))

        # Simple bar chart with consistent color
        bars1 = ax1.bar(x, df['Most Common TTL'], color='lightgreen')

        # Add percentage labels to TTL bars
        for i, (_, row) in enumerate(df.iterrows()):
            ax1.text(i, row['Most Common TTL'] + 1,
                     f"TTL: {row['Most Common TTL']:.0f}\n({row['TTL Percentage']:.1f}%)",
                     ha='center')

        # Removed horizontal reference lines as requested

        ax1.set_title('Most Common TTL Values by Application', fontsize=14)
        ax1.set_ylabel('TTL Value', fontsize=12)
        ax1.grid(axis='y', alpha=0.3)
        ax1.set_xticks(x)
        ax1.set_xticklabels(apps, rotation=30, ha='right')

        # Second subplot: Common IP Addresses (bar chart)
        # For each app, show top source and destination IP
        address_data = []
        for i, (_, row) in enumerate(df.iterrows()):
            app = row['Application']

            # Add top source IP
            if row['Top Source IPs']:
                top_src_ip, count, pct = row['Top Source IPs'][0]
                address_data.append({
                    'Application': app,
                    'IP Address': top_src_ip,
                    'Count': count,
                    'Percentage': pct,
                    'Type': 'Source'
                })

            # Add top destination IP
            if row['Top Destination IPs']:
                top_dst_ip, count, pct = row['Top Destination IPs'][0]
                address_data.append({
                    'Application': app,
                    'IP Address': top_dst_ip,
                    'Count': count,
                    'Percentage': pct,
                    'Type': 'Destination'
                })

        # Create DataFrame for IP addresses
        addr_df = pd.DataFrame(address_data)

        if not addr_df.empty:
            # Group by application and type
            sns.barplot(data=addr_df, x='Application', y='Percentage', hue='Type', ax=ax2)

            # Add IP address labels
            for i, row in addr_df.iterrows():
                app_idx = np.where(apps == row['Application'])[0][0]
                offset = -0.2 if row['Type'] == 'Source' else 0.2

                # Format IP for display (shorten if needed)
                ip_text = row['IP Address']
                if len(ip_text) > 15:
                    ip_parts = ip_text.split('.')
                    if len(ip_parts) == 4:  # IPv4
                        # Keep first and last octet
                        ip_text = f"{ip_parts[0]}.{ip_parts[1]}...{ip_parts[3]}"

                label_text = f"{ip_text}\n({row['Percentage']:.1f}%)"
                y_pos = row['Percentage'] + 1

                # Add the text label
                ax2.text(app_idx + offset, y_pos, label_text,
                         ha='center', va='bottom', fontsize=8, rotation=0)

            ax2.set_title('Most Common IP Addresses by Application', fontsize=14)
            ax2.set_ylabel('Percentage of Packets (%)', fontsize=12)
            ax2.set_xticks(x)
            ax2.set_xticklabels(apps, rotation=30, ha='right')
            ax2.grid(axis='y', alpha=0.3)

            # Add explanation
            plt.figtext(0.5, 0.01,
                        "Left: TTL values indicate how many hops a packet can traverse before being discarded.\n"
                        "Right: Most common source and destination IP addresses for each application.",
                        ha='center', fontsize=10,
                        bbox=dict(boxstyle='round,pad=0.5', facecolor='white', alpha=0.8))

            plt.tight_layout(rect=[0, 0.05, 1, 0.95])
            plt.savefig(plots_dir / 'ip_characteristics.png', dpi=300)
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

        # Get x positions and labels
        apps = df['Application'].values
        x = np.arange(len(apps))

        # Simple bar chart
        bars = plt.bar(x, df['Mean Window Size'], color='skyblue')

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
        plt.xticks(x, apps, rotation=30, ha='right')
        plt.tight_layout()

        plt.savefig(plots_dir / 'tcp_window_size.png', dpi=300)
        plt.close()

    def _plot_packet_sizes(self, plots_dir):
        """Plot packet size distributions with a creative bar and distribution approach"""
        size_data = []

        for app, features in self.results.items():
            # Skip if not enough data
            if not features['packet_size'] or len(features['packet_size']) < 10:
                continue

            # Calculate statistics
            packet_sizes = np.array(features['packet_size'])
            mean_val = np.mean(packet_sizes)
            median_val = np.median(packet_sizes)

            # Create size bins for better visualization
            # Create 5 size categories
            small = np.sum(packet_sizes < 200) / len(packet_sizes) * 100
            medium_small = np.sum((packet_sizes >= 200) & (packet_sizes < 600)) / len(packet_sizes) * 100
            medium = np.sum((packet_sizes >= 600) & (packet_sizes < 1000)) / len(packet_sizes) * 100
            medium_large = np.sum((packet_sizes >= 1000) & (packet_sizes < 1400)) / len(packet_sizes) * 100
            large = np.sum(packet_sizes >= 1400) / len(packet_sizes) * 100

            size_data.append({
                'Application': app,
                'Mean Size': mean_val,
                'Median Size': median_val,
                'Small (<200B)': small,
                'Medium-Small (200-600B)': medium_small,
                'Medium (600-1000B)': medium,
                'Medium-Large (1000-1400B)': medium_large,
                'Large (>1400B)': large,
                'Total Packets': len(packet_sizes)
            })

        if not size_data:
            return

        # Create DataFrame
        df = pd.DataFrame(size_data)

        # Sort by mean size
        df = df.sort_values('Mean Size', ascending=False)

        # Create a figure with two subplots side by side
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 10), gridspec_kw={'width_ratios': [1, 2]})

        # Get x positions and application names
        apps = df['Application'].values
        y_pos = np.arange(len(apps))

        # First subplot: Mean and median size comparison
        bars = ax1.barh(y_pos, df['Mean Size'], height=0.4, color='steelblue', alpha=0.8, label='Mean Size')
        ax1.barh(y_pos + 0.4, df['Median Size'], height=0.4, color='lightcoral', alpha=0.8, label='Median Size')

        # Add size labels
        for i, bar in enumerate(bars):
            # Add mean label
            ax1.text(df['Mean Size'].iloc[i] + 20, i, f"{df['Mean Size'].iloc[i]:.0f}B",
                     va='center', ha='left', color='navy', fontweight='bold')
            # Add median label
            ax1.text(df['Median Size'].iloc[i] + 20, i + 0.4, f"{df['Median Size'].iloc[i]:.0f}B",
                     va='center', ha='left', color='darkred', fontweight='bold')
            # Add packet count
            ax1.text(0, i + 0.2, f"Packets: {df['Total Packets'].iloc[i]:,}",
                     va='center', ha='left', color='black', fontsize=9)

        # Set up the y-axis with application names
        ax1.set_yticks(y_pos + 0.2)
        ax1.set_yticklabels(apps)

        # First subplot styling
        ax1.set_title('Average Packet Sizes by Application', fontsize=15, fontweight='bold')
        ax1.set_xlabel('Size in Bytes', fontsize=13)
        ax1.grid(axis='x', linestyle='--', alpha=0.6)
        ax1.legend(loc='upper right')

        # Second subplot: Size distribution
        size_categories = ['Small (<200B)', 'Medium-Small (200-600B)', 'Medium (600-1000B)',
                           'Medium-Large (1000-1400B)', 'Large (>1400B)']
        colors = ['#E1F5FE', '#81D4FA', '#4FC3F7', '#29B6F6', '#0288D1']  # Blue gradient

        # Create stacked bars for second subplot
        x_pos = np.arange(len(apps))

        # Create stacked bars
        bottom = np.zeros(len(df))
        for i, category in enumerate(size_categories):
            values = df[category].values
            b = ax2.bar(x_pos, values, bottom=bottom, label=category, color=colors[i])
            bottom += values

            # Add percentage labels if significant
            for j, value in enumerate(values):
                if value >= 10:  # Only show if at least 10%
                    text_y = bottom[j] - value / 2
                    ax2.text(j, text_y, f"{value:.0f}%", ha='center', va='center',
                             color='black', fontweight='bold')

        # Second subplot styling
        ax2.set_title('Packet Size Distribution by Category', fontsize=15, fontweight='bold')
        ax2.set_ylabel('Percentage of Packets', fontsize=13)
        ax2.set_ylim(0, 100)
        ax2.set_xticks(x_pos)
        ax2.set_xticklabels(apps, rotation=30, ha='right')
        ax2.grid(axis='y', linestyle='--', alpha=0.6)
        ax2.legend(title='Size Categories', bbox_to_anchor=(1.05, 1), loc='upper left')

        plt.tight_layout()
        plt.savefig(plots_dir / 'packet_size_boxplot.png', dpi=300)
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
            apps = df['Application'].values
            x = np.arange(len(apps))

            plt.figure(figsize=(10, 6))

            # Create the stacked bar chart
            plt.bar(x, df['Incoming'], width=0.7, label='Incoming', color='#6baed6')
            plt.bar(x, df['Outgoing'], width=0.7, bottom=df['Incoming'],
                    label='Outgoing', color='#3182bd')

            # Add percentage labels
            for i, (_, row) in enumerate(df.iterrows()):
                # Incoming percentage
                plt.text(i, row['Incoming'] / 2, f"{row['Incoming']:.1f}%",
                         ha='center', va='center', color='white', fontweight='bold')

                # Outgoing percentage
                plt.text(i, row['Incoming'] + row['Outgoing'] / 2, f"{row['Outgoing']:.1f}%",
                         ha='center', va='center', color='white', fontweight='bold')

            plt.title('Traffic Direction by Application')
            plt.ylabel('Percentage of Packets (%)')
            plt.legend(title='Direction')
            plt.grid(axis='y', linestyle='--', alpha=0.5)
            plt.xticks(x, apps, rotation=30, ha='right')
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