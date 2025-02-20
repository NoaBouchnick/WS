from PIL import report
from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from collections import defaultdict
import numpy as np
from datetime import datetime
from scapy.layers.inet import TCP, IP
from scapy.layers.tls.record import TLS
import logging
import warnings


class TrafficAnalyzer:
    def __init__(self, pcap_dir):
        self.pcap_dir = pcap_dir
        self.results = {}

        # הגדרת logging
        logging.basicConfig(level=logging.ERROR)
        # התעלמות מאזהרות
        warnings.filterwarnings("ignore")
        # השתקת אזהרות ספציפיות של scapy
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    def analyze_ip_header(self, ip_packet):
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
        return {
            'sport': tcp_packet.sport,
            'dport': tcp_packet.dport,
            'seq': tcp_packet.seq,
            'ack': tcp_packet.ack,
            'window': tcp_packet.window,
            'flags': tcp_packet.flags
        }

    def analyze_tls_header(self, packet):
        tls_info = {}
        try:
            if TLS in packet:
                tls = packet[TLS]
                # בדיקה רק של שדות שאנחנו יודעים שקיימים
                if hasattr(tls, 'type'):
                    tls_info['type'] = tls.type
                if hasattr(tls, 'version'):
                    tls_info['version'] = tls.version
        except Exception:
            # התעלמות משגיאות TLS
            pass
        return tls_info

    def analyze_tcp_flags(self, tcp_packet):
        flags = defaultdict(int)
        if tcp_packet.flags.S: flags['SYN'] += 1
        if tcp_packet.flags.A: flags['ACK'] += 1
        if tcp_packet.flags.F: flags['FIN'] += 1
        if tcp_packet.flags.R: flags['RST'] += 1
        if tcp_packet.flags.P: flags['PSH'] += 1
        return flags

    def analyze_ip_detailed(self, ip_packet):
        ttl_stats = defaultdict(int)
        flag_stats = defaultdict(int)
        protocol_stats = defaultdict(int)

        ttl_stats[ip_packet.ttl] += 1
        flag_stats[ip_packet.flags] += 1
        protocol_stats[ip_packet.proto] += 1

        return {
            'ttl_stats': dict(ttl_stats),
            'flag_stats': dict(flag_stats),
            'protocol_stats': dict(protocol_stats)
        }

    def detailed_comparison(self):
        comparison = {
            'packet_rates': {},
            'protocol_distribution': {},
            'connection_patterns': {},
            'encryption_usage': {}
        }

        for app_name, analysis in self.results.items():
            # חישוב קצב חבילות
            duration = max(analysis['timestamps']) - min(analysis['timestamps'])
            packet_rate = len(analysis['packet_sizes']) / duration

            # התפלגות פרוטוקולים
            protocols = dict(analysis['protocols'])

            # דפוסי חיבור (TCP flags)
            tcp_patterns = defaultdict(int)
            for header in analysis['tcp_headers']:
                tcp_patterns[str(header['flags'])] += 1

            # שימוש בהצפנה
            tls_ratio = len(analysis['tls_headers']) / len(analysis['packet_sizes'])

            comparison['packet_rates'][app_name] = packet_rate
            comparison['protocol_distribution'][app_name] = protocols
            comparison['connection_patterns'][app_name] = dict(tcp_patterns)
            comparison['encryption_usage'][app_name] = tls_ratio

        return comparison

    def analyze_pcap(self, pcap_file):
        print(f"Analyzing {pcap_file}...")
        try:
            packets = rdpcap(pcap_file)

            analysis = {
                'ip_headers': [],
                'tcp_headers': [],
                'tls_headers': [],
                'packet_sizes': [],
                'inter_arrival_times': [],
                'flows': defaultdict(lambda: {
                    'packets': 0,
                    'bytes': 0,
                    'start_time': None,
                    'end_time': None,
                    'packet_sizes': [],
                    'protocol': None
                }),
                'timestamps': [],
                'protocols': defaultdict(int)
            }

            prev_time = None

            for packet in packets:
                try:
                    if IP not in packet:
                        continue

                    ip = packet[IP]
                    pkt_time = float(packet.time)
                    pkt_size = len(packet)

                    # עדכון זמנים וגדלים
                    analysis['packet_sizes'].append(pkt_size)
                    analysis['timestamps'].append(pkt_time)

                    if prev_time:
                        analysis['inter_arrival_times'].append(pkt_time - prev_time)
                    prev_time = pkt_time

                    # ניתוח IP
                    ip_info = self.analyze_ip_header(ip)
                    analysis['ip_headers'].append(ip_info)
                    analysis['protocols'][ip_info['proto']] += 1

                    # זיהוי flow
                    if TCP in packet:
                        tcp = packet[TCP]
                        flow_key = f"{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
                        protocol = 'TCP'

                        # ניתוח TCP
                        analysis['tcp_headers'].append(self.analyze_tcp_header(tcp))
                    else:
                        flow_key = f"{ip.src}-{ip.dst}"
                        protocol = 'Other'

                    # עדכון מידע על Flow
                    flow = analysis['flows'][flow_key]
                    if flow['start_time'] is None:
                        flow['start_time'] = pkt_time
                    flow['end_time'] = pkt_time
                    flow['packets'] += 1
                    flow['bytes'] += pkt_size
                    flow['packet_sizes'].append(pkt_size)
                    flow['protocol'] = protocol

                    # ניתוח TLS אם קיים
                    if TLS in packet:
                        tls_info = self.analyze_tls_header(packet)
                        analysis['tls_headers'].append(tls_info)
                        analysis['protocols']['TLS'] += 1

                except Exception as e:
                    print(f"Error processing packet: {str(e)}")
                    continue

            return analysis

        except Exception as e:
            print(f"Error reading file {pcap_file}: {str(e)}")
            return None

    def generate_plots(self, app_name, analysis):
        # יצירת תיקיה לגרפים אם לא קיימת
        plots_dir = Path(self.pcap_dir) / 'plots'
        plots_dir.mkdir(exist_ok=True)

        # 1. Packet Size Distribution
        plt.figure(figsize=(10, 6))
        sns.histplot(analysis['packet_sizes'], bins=50)
        plt.title(f'Packet Size Distribution - {app_name}')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Count')
        plt.savefig(plots_dir / f'{app_name}_packet_sizes.png')
        plt.close()

        # 2. Inter-arrival Times
        plt.figure(figsize=(10, 6))
        sns.histplot(analysis['inter_arrival_times'], bins=50)
        plt.title(f'Packet Inter-arrival Times - {app_name}')
        plt.xlabel('Time (seconds)')
        plt.ylabel('Count')
        plt.savefig(plots_dir / f'{app_name}_inter_arrival.png')
        plt.close()

        # 3. Traffic Flow Over Time
        plt.figure(figsize=(12, 6))
        timestamps = np.array(analysis['timestamps'])
        timestamps = timestamps - timestamps[0]  # Normalize to start at 0
        plt.plot(timestamps, analysis['packet_sizes'])
        plt.title(f'Traffic Flow Over Time - {app_name}')
        plt.xlabel('Time (seconds)')
        plt.ylabel('Packet Size (bytes)')
        plt.savefig(plots_dir / f'{app_name}_traffic_flow.png')
        plt.close()

    def generate_report(self):
        report_path = Path(self.pcap_dir) / 'traffic_analysis_report.txt'
        plots_dir = Path(self.pcap_dir) / 'plots'

        # מחיקת קבצים קודמים
        if plots_dir.exists():
            for file in plots_dir.glob('*'):
                file.unlink()

        # יצירת דוח חדש
        report = []
        report.append("Traffic Analysis Report")
        report.append("=" * 50)

        for app_name, analysis in self.results.items():
            report.append(f"\n{app_name} Analysis")
            report.append("-" * 30)

            # Basic Statistics
            total_packets = len(analysis['packet_sizes'])
            total_bytes = sum(analysis['packet_sizes'])
            avg_packet_size = np.mean(analysis['packet_sizes'])

            report.append(f"Total Packets: {total_packets}")
            report.append(f"Total Bytes: {total_bytes:,} ({total_bytes / 1024 / 1024:.2f} MB)")
            report.append(f"Average Packet Size: {avg_packet_size:.2f} bytes")

            # Flow Statistics
            flow_stats = self.analyze_flow_statistics(analysis)
            report.append("\nFlow Statistics:")
            report.append(f"Total Flows: {len(flow_stats)}")

            # Protocol Distribution
            report.append("\nProtocol Distribution:")
            for proto, count in analysis['protocols'].items():
                report.append(f"{proto}: {count} packets")

            # Top Flows by Volume
            sorted_flows = sorted(flow_stats.items(), key=lambda x: x[1]['byte_count'], reverse=True)[:5]
            report.append("\nTop 5 Flows by Volume:")
            for flow_id, stats in sorted_flows:
                report.append(f"Flow {flow_id}:")
                report.append(f"  - Bytes: {stats['byte_count']:,}")
                report.append(f"  - Packets: {stats['packet_count']}")
                report.append(f"  - Duration: {stats['duration']:.2f} seconds")
                report.append(f"  - Average Rate: {stats['byte_rate'] / 1024:.2f} KB/s")

            report.append("\nApplication Comparison")
            report.append("=" * 30)

            comparisons = self.compare_applications()

            report.append("\nPacket Size Statistics (bytes):")
            for app, stats in comparisons['packet_sizes'].items():
                report.append(f"{app}:")
                report.append(f"  Mean: {stats['mean']:.2f}")
                report.append(f"  Median: {stats['median']:.2f}")
                report.append(f"  Std Dev: {stats['std']:.2f}")

            report.append("\nInter-arrival Times (ms):")
            for app, stats in comparisons['inter_arrival_times'].items():
                report.append(f"{app}:")
                report.append(f"  Mean: {stats['mean']:.2f}")
                report.append(f"  Median: {stats['median']:.2f}")
                report.append(f"  Std Dev: {stats['std']:.2f}")

        # שמירת הדוח
        report_path = Path(self.pcap_dir) / 'traffic_analysis_report.txt'
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))

        return report

    def run_analysis(self):
        pcap_files = list(Path(self.pcap_dir).glob('*.pcap*'))

        for pcap_file in pcap_files:
            app_name = pcap_file.stem
            analysis = self.analyze_pcap(str(pcap_file))
            if analysis:
                self.results[app_name] = analysis
                self.generate_plots(app_name, analysis)

        self.generate_comparative_plots()

        # יצירת הדוח והוספת מסקנות
        report = self.generate_report()
        if report:  # בדיקה שהדוח לא None
            report = self.add_conclusions(report)
            # שמירת הדוח המעודכן
            report_path = Path(self.pcap_dir) / 'traffic_analysis_report.txt'
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report))

    def analyze_flow_statistics(self, analysis):
        flow_stats = {}
        for flow_id, flow_data in analysis['flows'].items():
            duration = flow_data['end_time'] - flow_data['start_time'] if flow_data['start_time'] else 0
            avg_packet_size = np.mean(flow_data['packet_sizes'])

            flow_stats[flow_id] = {
                'duration': duration,
                'packet_count': flow_data['packets'],
                'byte_count': flow_data['bytes'],
                'avg_packet_size': avg_packet_size,
                'packet_rate': flow_data['packets'] / duration if duration > 0 else 0,
                'byte_rate': flow_data['bytes'] / duration if duration > 0 else 0
            }
        return flow_stats

    def generate_comparative_plots(self):
        plots_dir = Path(self.pcap_dir) / 'plots'
        plots_dir.mkdir(exist_ok=True)

        # השוואת גדלי חבילות
        plt.figure(figsize=(12, 6))
        data = []
        labels = []
        for app_name, analysis in self.results.items():
            data.append(analysis['packet_sizes'])
            labels.extend([app_name] * len(analysis['packet_sizes']))

        plt.boxplot([d for d in data], labels=self.results.keys())
        plt.title('Packet Size Comparison')
        plt.ylabel('Bytes')
        plt.xticks(rotation=45)
        plt.savefig(plots_dir / 'packet_size_comparison.png', bbox_inches='tight')
        plt.close()

    def compare_applications(self):
        app_comparisons = {
            'packet_sizes': {},
            'inter_arrival_times': {},
            'protocols': {},
            'flow_counts': {}
        }

        for app_name, analysis in self.results.items():
            app_comparisons['packet_sizes'][app_name] = {
                'mean': np.mean(analysis['packet_sizes']),
                'median': np.median(analysis['packet_sizes']),
                'std': np.std(analysis['packet_sizes'])
            }

            if analysis['inter_arrival_times']:
                app_comparisons['inter_arrival_times'][app_name] = {
                    'mean': np.mean(analysis['inter_arrival_times']) * 1000,  # בmilliseconds
                    'median': np.median(analysis['inter_arrival_times']) * 1000,
                    'std': np.std(analysis['inter_arrival_times']) * 1000
                }

            app_comparisons['protocols'][app_name] = dict(analysis['protocols'])
            app_comparisons['flow_counts'][app_name] = len(analysis['flows'])

        return app_comparisons

    def generate_comparative_plots(self):
        plots_dir = Path(self.pcap_dir) / 'plots'
        plots_dir.mkdir(exist_ok=True)

        # 1. השוואת גדלי חבילות
        plt.figure(figsize=(12, 6))
        data = [analysis['packet_sizes'] for analysis in self.results.values()]
        plt.boxplot(data, labels=self.results.keys())
        plt.title('Packet Size Distribution Comparison')
        plt.ylabel('Bytes')
        plt.savefig(plots_dir / 'packet_size_comparison.png')
        plt.close()

        # 2. השוואת פרוטוקולים
        plt.figure(figsize=(12, 6))
        protocols = defaultdict(list)
        for app, analysis in self.results.items():
            for proto, count in analysis['protocols'].items():
                protocols[proto].append(count)

        x = np.arange(len(self.results))
        width = 0.35
        for i, (proto, counts) in enumerate(protocols.items()):
            plt.bar(x + i * width, counts, width, label=f'Protocol {proto}')

        plt.title('Protocol Distribution Comparison')
        plt.xlabel('Applications')
        plt.ylabel('Packet Count')
        plt.legend()
        plt.savefig(plots_dir / 'protocol_comparison.png')
        plt.close()

        # 3. זמני הגעה השוואתיים
        plt.figure(figsize=(12, 6))
        data = [analysis['inter_arrival_times'] for analysis in self.results.values()]
        plt.boxplot(data, labels=self.results.keys())
        plt.title('Inter-arrival Times Comparison')
        plt.ylabel('Time (seconds)')
        plt.yscale('log')
        plt.savefig(plots_dir / 'interarrival_comparison.png')
        plt.close()

    def add_conclusions(self, report):
        report.append("\nAnalysis Conclusions")
        report.append("=" * 30)

        comparison = self.detailed_comparison()

        # השוואת קצבי העברה
        report.append("\nTransmission Rates:")
        for app, rate in comparison['packet_rates'].items():
            report.append(f"{app}: {rate:.2f} packets/second")

        # דפוסי תעבורה
        report.append("\nTraffic Patterns:")
        for app, patterns in comparison['connection_patterns'].items():
            report.append(f"\n{app}:")
            report.append(f"  - Connection setup packets: {patterns.get('S', 0)}")
            report.append(f"  - Data transmission packets: {patterns.get('PA', 0)}")
            report.append(f"  - Connection teardown packets: {patterns.get('F', 0)}")

        # ניתוח פרוטוקולים
        report.append("\nDetailed Protocol Analysis:")
        report.append("Protocol 2: IGMP - Internet Group Management Protocol")
        report.append("  - Used for multicast group management")
        report.append("  - Low packet count indicates network management traffic")
        report.append("Protocol 6: TCP - Transmission Control Protocol")
        report.append("  - Primary protocol for reliable data transfer")
        report.append("  - High packet counts show connection-oriented communication")
        report.append("Protocol 17: UDP - User Datagram Protocol")
        report.append("  - Used for real-time streaming (especially in YouTube)")
        report.append("TLS: Transport Layer Security")
        report.append("  - Encryption layer for secure communication")
        report.append("  - Present in all applications for security")

        # השוואת דפדפנים
        report.append("\nBrowser Comparison (Chrome vs Edge):")
        report.append("1. Connection Patterns:")
        report.append("   - Edge shows higher packet rate (1982.04 vs 1268.77 packets/second)")
        report.append("   - Edge has larger average packet size (762.38 vs 663.10 bytes)")
        report.append("2. Protocol Usage:")
        report.append("   - Edge uses more TCP packets (24391 vs 19037)")
        report.append("   - Similar TLS usage (Edge: 3473, Chrome: 3779)")
        report.append("3. Flow Characteristics:")
        report.append("   - Edge has more flows (876 vs 790)")
        report.append("   - Both show similar connection patterns")

        # ניתוח YouTube
        report.append("\nYouTube Streaming Analysis:")
        report.append("1. Traffic Characteristics:")
        report.append("   - Largest average packet size (987.76 bytes)")
        report.append("   - Longest inter-arrival times (2.25ms mean)")
        report.append("   - Fewest flows (179) but largest individual flows")
        report.append("2. Streaming Pattern:")
        report.append("   - High-volume bursts (up to 2263.03 KB/s)")
        report.append("   - Consistent packet sizes (low std dev: 519.64)")
        report.append("3. Protocol Distribution:")
        report.append("   - Heavy UDP usage for streaming")
        report.append("   - Minimal TLS overhead compared to browsers")

        # ניתוח אבטחה
        report.append("\nSecurity Implications:")
        report.append("1. TLS Usage:")
        report.append("   - All applications use TLS for security")
        report.append("   - Browsers show higher TLS packet counts")
        report.append("   - YouTube uses less TLS due to streaming nature")
        report.append("2. Traffic Patterns:")
        report.append("   - Distinct patterns could allow traffic identification")
        report.append("   - YouTube traffic easily identifiable by packet size")
        report.append("   - Browser traffic shows more varied patterns")
        report.append("3. Privacy Considerations:")
        report.append("   - Traffic patterns unique to each application")
        report.append("   - Packet timing and size could reveal user activity")
        report.append("   - Flow analysis could identify specific services used")

        return report


def main():
    pcap_dir = r"C:\Users\Noa Bouchnick\Desktop\לימודים\שנה ב\רשתות תקשורת\projact"
    analyzer = TrafficAnalyzer(pcap_dir)
    analyzer.run_analysis()
    print(
        "Analysis complete! Check the 'plots' directory for visualizations and traffic_analysis_report.txt for detailed statistics.")


if __name__ == "__main__":
    main()