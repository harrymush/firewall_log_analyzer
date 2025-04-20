import re
from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd


log_pattern = re.compile(
    r"SRC=(?P<src_ip>\S+)\sDST=(?P<dst_ip>\S+).*PROTO=(?P<proto>\S+)\s(?:.*SPT=(?P<src_port>\d+)\sDPT=(?P<dst_port>\d+))?"
)

def analyze_logs(log_file, request_threshold=10):
    stats = defaultdict(int)
    src_ip_stats = defaultdict(int)
    dst_port_stats = defaultdict(int)
    log_entries = []  # Initialize list to store log entries

    try:
        with open(log_file, "r") as file:
            for line in file:
                match = log_pattern.search(line)
                if match:
                    data = match.groupdict()

                    log_entries.append({
                        "src_ip": data.get("src_ip"),
                        "dst_ip": data.get("dst_ip"),
                        "proto": data.get("proto"),
                        "src_port": data.get("src_port"),
                        "dst_port": data.get("dst_port"),
                    })

                    # Keep this too, for plotting
                    stats[f"src_ip:{data.get('src_ip')}"] += 1
                    stats[f"proto:{data.get('proto')}"] += 1
                    if data.get("dst_port"):
                        stats[f"dst_port:{data.get('dst_port')}"] += 1

                    # Store specific stats for visualization
                    src_ip_stats[data.get("src_ip")] += 1
                    if data.get("dst_port"):
                        dst_port_stats[data.get("dst_port")] += 1

        print("\n--- Summary ---")
        for key, count in sorted(stats.items(), key=lambda x: -x[1]):
            print(f"{key} -> {count} times")

        # Visualize the results
        visualize_top_offenders(src_ip_stats, dst_port_stats)

        df = pd.DataFrame(log_entries)

        print("\nTop Source IPs:")
        print(df["src_ip"].value_counts().head(5))

        print("\nTop Destination Ports:")
        print(df["dst_port"].value_counts().head(5))

        print("\nTop Protocols:")
        print(df["proto"].value_counts().head(5))

        # Save parsed logs to CSV
        df.to_csv("logs/parsed_output.csv", index=False)
        print("\nSaved full parsed log to logs/parsed_output.csv")

        # Run suspicious activity detection
        detect_suspicious(df, request_threshold=request_threshold)

    except FileNotFoundError:
        print(f"Log file not found: {log_file}")

def visualize_top_offenders(src_ip_stats, dst_port_stats, top_n=10):
    # Create a figure with two subplots side by side
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # Sort and get top N source IPs
    top_ips = dict(sorted(src_ip_stats.items(), key=lambda x: x[1], reverse=True)[:top_n])
    ax1.bar(top_ips.keys(), top_ips.values())
    ax1.set_title('Top Source IPs')
    ax1.set_xlabel('Source IP')
    ax1.set_ylabel('Number of Attempts')
    plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')

    # Sort and get top N destination ports
    top_ports = dict(sorted(dst_port_stats.items(), key=lambda x: x[1], reverse=True)[:top_n])
    ax2.bar(top_ports.keys(), top_ports.values())
    ax2.set_title('Top Destination Ports')
    ax2.set_xlabel('Destination Port')
    ax2.set_ylabel('Number of Attempts')
    plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')

    # Adjust layout to prevent label cutoff
    plt.tight_layout()
    
    # Save the plot
    plt.savefig('firewall_analysis.png')
    plt.close()

def detect_suspicious(df, request_threshold=10):
    print("\n🔍 Suspicious Activity Report")

    # High-frequency IPs
    ip_counts = df["src_ip"].value_counts()
    high_freq_ips = ip_counts[ip_counts > request_threshold]

    if not high_freq_ips.empty:
        print(f"\n🚨 IPs with more than {request_threshold} requests:")
        print(high_freq_ips)
    else:
        print("\n✅ No IPs exceeded the request threshold.")

    # Suspicious ports
    sensitive_ports = {"22", "23", "3389", "3306", "1433", "8080"}
    hits = df[df["dst_port"].isin(sensitive_ports)]

    if not hits.empty:
        print(f"\n🚪 Connections to sensitive ports:")
        print(hits[["src_ip", "dst_port", "proto"]].drop_duplicates())
    else:
        print("\n✅ No connections to common sensitive ports.")

    # Weird protocols
    common_protocols = {"TCP", "UDP"}
    unknown_proto = df[~df["proto"].isin(common_protocols)]

    if not unknown_proto.empty:
        print("\n👽 Unknown or uncommon protocols detected:")
        print(unknown_proto["proto"].value_counts())
    else:
        print("\n✅ No unusual protocols detected.")
