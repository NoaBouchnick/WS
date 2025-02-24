# Import statements at module level
from telnetlib import TLS, IP

from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import numpy as np
import os
import logging
import warnings
from collections import defaultdict

from scapy.layers.inet import TCP, UDP

# השתק אזהרות מיותרות
logging.basicConfig(level=logging.ERROR)
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class TrafficAnalyzer:
    def __init__(self, pcap_dir):
        self.pcap_dir = pcap_dir
        self.results = {}
        self.app_names = []

    def analyze_pcap(self, pcap_file):
        """Analyze a single PCAP file using pandas for data processing"""
        print(f"Analyzing {pcap_file}...")
        try:
            # קריאת חבילות
            packets = rdpcap(pcap_file)

            # אתחול מבנה הנתונים
            data = {
                'packet_sizes': [],
                'timestamps': [],
                'inter_arrival_times': [],
                'protocols': defaultdict(int),
                'ttl_values': [],
                'ihl_values': [],
                'tcp_window_sizes': [],
                'tcp_flags': defaultdict(int),
                'tcp_dports': [],
                'tls_versions': defaultdict(int),
                'tls_types': defaultdict(int),
                'tls_headers': []
            }

            prev_time = None

            # ניתוח חבילות
            for packet in packets:
                if IP not in packet:
                    continue

                ip = packet[IP]
                pkt_time = float(packet.time)
                pkt_size = len(packet)

                # תזמונים וגדלים
                data['packet_sizes'].append(pkt_size)
                data['timestamps'].append(pkt_time)
                data['ttl_values'].append(ip.ttl)
                data['ihl_values'].append(ip.ihl)

                if prev_time:
                    data['inter_arrival_times'].append(pkt_time - prev_time)
                prev_time = pkt_time

                # IP פרוטוקולים
                data['protocols'][ip.proto] += 1

                # TCP ניתוח
                if TCP in packet:
                    tcp = packet[TCP]
                    data['tcp_window_sizes'].append(tcp.window)
                    data['tcp_dports'].append(tcp.dport)
                    data['tcp_flags'][str(tcp.flags)] += 1

                # UDP וזיהוי QUIC
                if UDP in packet:
                    udp = packet[UDP]
                    data['protocols']['UDP'] += 1

                    # בדיקת QUIC על פורט 443
                    if udp.dport == 443 or udp.sport == 443:
                        data['protocols']['QUIC'] += 1

                # TLS ניתוח
                if TLS in packet:
                    tls = packet[TLS]
                    data['protocols']['TLS'] += 1
                    data['tls_headers'].append(1)  # רק לספירה

                    if hasattr(tls, 'type'):
                        data['tls_types'][tls.type] += 1
                    if hasattr(tls, 'version'):
                        data['tls_versions'][tls.version] += 1

            return data

        except Exception as e:
            print(f"Error reading file {pcap_file}: {str(e)}")
            return None

    def run_analysis(self):
        """Run analysis on all PCAP files in the directory"""
        pcap_files = list(Path(self.pcap_dir).glob('*.pcap*'))

        for pcap_file in pcap_files:
            app_name = pcap_file.stem
            self.app_names.append(app_name)
            data = self.analyze_pcap(str(pcap_file))
            if data:
                self.results[app_name] = data

        # יצירת תיקייה לגרפים
        plots_dir = Path(self.pcap_dir) / 'plots'
        plots_dir.mkdir(exist_ok=True)

        # יצירת כל הגרפים
        self.generate_plots(plots_dir)
        self.generate_report(plots_dir)

        print("Analysis complete! Check the 'plots' directory for visualizations.")

    def generate_plots(self, plots_dir):
        """Generate all plots with fewer lines of code"""
        print("Generating plots...")

        # יצירת טבלת סטטיסטיקות מרכזית
        stats_df = self.create_stats_dataframe()
        stats_df.to_csv(plots_dir / 'traffic_comparison_summary.csv', index=False)

        # 1. גרף השוואת פרוטוקולים
        self.plot_protocol_comparison(stats_df, plots_dir)

        # 2. גרף השוואת גדלי חבילות
        self.plot_packet_sizes(plots_dir)

        # 3. גרף השוואת שדות כותרת IP
        self.plot_ip_headers(plots_dir)

        # 4. גרף השוואת פרמטרי TCP
        self.plot_tcp_parameters(plots_dir)

        # 5. גרף השוואת סוגי TLS
        self.plot_tls_parameters(plots_dir)

    def create_stats_dataframe(self):
        """Create a statistics dataframe for comparison"""
        stats = []

        for app in self.results:
            packet_sizes = self.results[app]['packet_sizes']
            inter_arrival = self.results[app]['inter_arrival_times']
            total_packets = len(packet_sizes)

            app_stats = {
                'Application': app,
                'Total Packets': total_packets,
                'Avg Packet Size': np.mean(packet_sizes) if packet_sizes else 0,
                'Median Packet Size': np.median(packet_sizes) if packet_sizes else 0,
                'Std Dev Packet Size': np.std(packet_sizes) if packet_sizes else 0,
                'Avg Inter-arrival Time': np.mean(inter_arrival) * 1000 if inter_arrival else 0,
                'TCP %': (self.results[app]['protocols'].get(6, 0) / total_packets * 100) if total_packets else 0,
                'UDP %': (self.results[app]['protocols'].get(17, 0) / total_packets * 100) if total_packets else 0,
                'TLS %': (len(self.results[app]['tls_headers']) / total_packets * 100) if total_packets else 0
            }

            # הוספת QUIC אם קיים
            if 'QUIC' in self.results[app]['protocols']:
                app_stats['QUIC %'] = (
                            self.results[app]['protocols']['QUIC'] / total_packets * 100) if total_packets else 0
            else:
                app_stats['QUIC %'] = 0

            stats.append(app_stats)

        return pd.DataFrame(stats)

    def plot_protocol_comparison(self, stats_df, plots_dir):
        """Plot protocol comparison charts"""
        # גרף השוואת פרוטוקולים באחוזים
        plt.figure(figsize=(12, 6))
        protocols = ['TCP %', 'UDP %', 'TLS %', 'QUIC %']

        # שימוש בפנדס לציור גרף קל יותר
        stats_df[protocols].plot(kind='bar', figsize=(10, 6))
        plt.title('Protocol Usage Comparison')
        plt.ylabel('Percentage of Packets')
        plt.xlabel('Application')
        plt.legend(title='Protocol')
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.savefig(plots_dir / 'protocol_comparison.png', dpi=300)
        plt.close()

        # גרף פרוטוקולים מוערם
        app_data = []
        for app in self.results:
            proto_counts = {}
            total = len(self.results[app]['packet_sizes'])
            for proto, count in self.results[app]['protocols'].items():
                if isinstance(proto, int):
                    proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, f'Proto-{proto}')
                else:
                    proto_name = proto
                proto_counts[proto_name] = count

            app_data.append({
                'Application': app,
                **proto_counts
            })

        # המרה לפנדס DataFrame
        proto_df = pd.DataFrame(app_data).fillna(0)
        proto_df = proto_df.set_index('Application')

        # ציור גרף עמודות מוערם
        proto_df.plot(kind='bar', stacked=True, figsize=(12, 6))
        plt.title('Protocol Distribution')
        plt.ylabel('Packet Count')
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.savefig(plots_dir / 'protocol_stacked.png', dpi=300)
        plt.close()

    def plot_packet_sizes(self, plots_dir):
        """Plot packet size comparisons"""
        # יצירת boxplot השוואתי
        plt.figure(figsize=(12, 6))

        data = [self.results[app]['packet_sizes'] for app in self.results]
        labels = list(self.results.keys())

        # שימוש בסיבורן לגרפיקה משופרת
        sns.boxplot(data=data)
        plt.xticks(range(len(labels)), labels, rotation=45)
        plt.title('Packet Size Comparison', fontsize=14)
        plt.ylabel('Size (bytes)', fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.savefig(plots_dir / 'packet_size_boxplot.png', dpi=300)
        plt.close()

        # יצירת קו צפיפות למחקר השוואתי
        plt.figure(figsize=(12, 6))

        for app in self.results:
            sns.kdeplot(self.results[app]['packet_sizes'], label=app)

        plt.title('Packet Size Distribution Comparison', fontsize=14)
        plt.xlabel('Packet Size (bytes)', fontsize=12)
        plt.ylabel('Density', fontsize=12)
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.savefig(plots_dir / 'packet_size_density.png', dpi=300)
        plt.close()

    def plot_ip_headers(self, plots_dir):
        """Plot IP header field comparisons"""
        # השוואת TTL
        plt.figure(figsize=(12, 6))

        data = [self.results[app]['ttl_values'] for app in self.results]
        labels = list(self.results.keys())

        # יצירת boxplot יפה עם סיבורן
        sns.boxplot(data=data)
        plt.xticks(range(len(labels)), labels, rotation=45)
        plt.title('IP TTL Comparison', fontsize=14)
        plt.ylabel('TTL Value', fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.savefig(plots_dir / 'ip_ttl_boxplot.png', dpi=300)
        plt.close()

        # השוואת אורך כותרת IP
        plt.figure(figsize=(12, 6))

        data = [self.results[app]['ihl_values'] for app in self.results]

        sns.boxplot(data=data)
        plt.xticks(range(len(labels)), labels, rotation=45)
        plt.title('IP Header Length Comparison', fontsize=14)
        plt.ylabel('IHL (32-bit words)', fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.savefig(plots_dir / 'ip_ihl_boxplot.png', dpi=300)
        plt.close()

    def plot_tcp_parameters(self, plots_dir):
        """Plot TCP parameter comparisons"""
        # השוואת גודל חלון TCP
        plt.figure(figsize=(12, 6))

        data = [self.results[app]['tcp_window_sizes'] for app in self.results]
        labels = list(self.results.keys())

        valid_data = []
        valid_labels = []
        for d, label in zip(data, labels):
            if d and len(d) > 0:
                valid_data.append(d)
                valid_labels.append(label)

        if valid_data:
            sns.boxplot(data=valid_data)
            plt.xticks(range(len(valid_labels)), valid_labels, rotation=45)
            plt.title('TCP Window Size Comparison', fontsize=14)
            plt.ylabel('Window Size', fontsize=12)
            plt.grid(True, linestyle='--', alpha=0.3)
            plt.tight_layout()
            plt.savefig(plots_dir / 'tcp_window_boxplot.png', dpi=300)
        plt.close()

        # דגלי TCP
        plt.figure(figsize=(14, 8))

        # הכנת נתונים לתרשים עמודות
        all_flags = set()
        flag_data = {}

        for app in self.results:
            flag_data[app] = dict(self.results[app]['tcp_flags'])
            all_flags.update(flag_data[app].keys())

        if all_flags:
            # המרה ל-DataFrame
            flag_df = pd.DataFrame({app: {flag: flag_data[app].get(flag, 0) for flag in all_flags}
                                    for app in self.results}).T

            # ציור תרשים
            flag_df.plot(kind='bar', figsize=(14, 8))
            plt.title('TCP Flags Distribution', fontsize=14)
            plt.ylabel('Packet Count', fontsize=12)
            plt.xlabel('Application', fontsize=12)
            plt.legend(title='Flags')
            plt.grid(True, linestyle='--', alpha=0.3)
            plt.tight_layout()
            plt.savefig(plots_dir / 'tcp_flags_bars.png', dpi=300)
        plt.close()

    def plot_tls_parameters(self, plots_dir):
        """Plot TLS parameter comparisons"""
        # גרסאות TLS
        if any('tls_versions' in self.results[app] and self.results[app]['tls_versions'] for app in self.results):
            plt.figure(figsize=(14, 8))

            # שמות גרסאות TLS
            tls_names = {
                0x0301: 'TLS 1.0',
                0x0302: 'TLS 1.1',
                0x0303: 'TLS 1.2',
                0x0304: 'TLS 1.3'
            }

            # הכנת DataFrame
            version_data = {}
            for app in self.results:
                if 'tls_versions' in self.results[app]:
                    version_counts = {}
                    for ver, count in self.results[app]['tls_versions'].items():
                        ver_name = tls_names.get(ver, f'Unknown (0x{ver:04x})')
                        version_counts[ver_name] = count
                    version_data[app] = version_counts

            if version_data:
                # המרה ל-DataFrame
                version_df = pd.DataFrame(version_data).fillna(0)

                # ציור תרשים
                version_df.plot(kind='bar', figsize=(14, 8))
                plt.title('TLS Version Distribution', fontsize=14)
                plt.ylabel('Packet Count', fontsize=12)
                plt.xlabel('TLS Version', fontsize=12)
                plt.legend(title='Application')
                plt.grid(True, linestyle='--', alpha=0.3)
                plt.tight_layout()
                plt.savefig(plots_dir / 'tls_version_bars.png', dpi=300)
            plt.close()

    def generate_report(self, plots_dir):
        """Generate a text report summarizing the analysis"""
        with open(plots_dir / 'analysis_report.txt', 'w') as f:
            f.write("Network Traffic Analysis Report\n")
            f.write("==============================\n\n")

            # סטטיסטיקה כללית
            stats_df = self.create_stats_dataframe()
            f.write("General Statistics:\n")
            f.write(stats_df.to_string(index=False))
            f.write("\n\n")

            # ניתוח מפורט לכל אפליקציה
            for app in self.results:
                f.write(f"\n{app} Analysis\n")
                f.write("-" * 30 + "\n")

                data = self.results[app]
                total_packets = len(data['packet_sizes'])

                f.write(f"Total Packets: {total_packets}\n")
                f.write(f"Total Data: {sum(data['packet_sizes']) / 1024 / 1024:.2f} MB\n")
                f.write(f"Average Packet Size: {np.mean(data['packet_sizes']):.2f} bytes\n")
                f.write(f"Median Packet Size: {np.median(data['packet_sizes']):.2f} bytes\n")

                # התפלגות פרוטוקולים
                f.write("\nProtocol Distribution:\n")
                for proto, count in data['protocols'].items():
                    if isinstance(proto, int):
                        proto_name = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP'}.get(proto, f'Protocol {proto}')
                    else:
                        proto_name = proto
                    f.write(f"  {proto_name}: {count} packets ({count / total_packets * 100:.2f}%)\n")

                # סיכום TLS
                if 'tls_headers' in data and data['tls_headers']:
                    tls_count = len(data['tls_headers'])
                    f.write(f"\nTLS Information:\n")
                    f.write(f"  Total TLS Packets: {tls_count} ({tls_count / total_packets * 100:.2f}%)\n")

                # סיכום QUIC
                if 'QUIC' in data['protocols'] and data['protocols']['QUIC'] > 0:
                    quic_count = data['protocols']['QUIC']
                    f.write(f"\nQUIC Information:\n")
                    f.write(f"  Total QUIC Packets: {quic_count} ({quic_count / total_packets * 100:.2f}%)\n")

                f.write("\n" + "=" * 50 + "\n")


def main():
    # קבלת נתיב התיקייה מהמשתמש
    pcap_dir = input("Enter the directory path containing PCAP files (or press Enter to use current directory): ")

    if not pcap_dir:
        pcap_dir = os.getcwd()

    analyzer = TrafficAnalyzer(pcap_dir)
    analyzer.run_analysis()


if __name__ == "__main__":
    main()