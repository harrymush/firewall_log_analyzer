import argparse
import os
from src.analyzer import analyze_logs

def main():
    parser = argparse.ArgumentParser(description='Firewall Log Analyzer')
    parser.add_argument('log_file', nargs='?', default='logs/sample.log',
                      help='Path to the firewall log file (default: logs/sample.log)')
    parser.add_argument('--threshold', '-t', type=int, default=10,
                      help='Request threshold for suspicious activity detection (default: 10)')
    
    args = parser.parse_args()

    # Check if log file exists
    if not os.path.exists(args.log_file):
        print(f"Error: Log file '{args.log_file}' not found.")
        print("\nTo use this tool:")
        print("1. Place your firewall log file in the 'logs' directory")
        print("2. Run: python app.py [path/to/your/logfile]")
        print("   or: python app.py --threshold 20 [path/to/your/logfile]")
        return

    print(f"Analyzing firewall logs from: {args.log_file}")
    print(f"Using suspicious activity threshold: {args.threshold}")
    print("-" * 50)
    
    try:
        analyze_logs(args.log_file, request_threshold=args.threshold)
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        print("\nMake sure your log file matches the expected format:")
        print("SRC=<source_ip> DST=<destination_ip> PROTO=<protocol> SPT=<source_port> DPT=<destination_port>")

if __name__ == "__main__":
    main()
