# Firewall Log Analyzer

A Python tool for analyzing firewall logs, detecting suspicious activity, and generating visualizations.

## Features

- Parse and analyze firewall logs
- Generate statistics about source IPs, destination ports, and protocols
- Detect suspicious activity patterns
- Create visualizations of top offenders
- Export parsed data to CSV for further analysis
- Customizable suspicious activity thresholds

## Installation

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd firewall_log_analyzer
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   # On macOS/Linux
   python -m venv venv
   source venv/bin/activate

   # On Windows
   python -m venv venv
   venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

1. Place your firewall log file in the `logs` directory
2. Run the analyzer:
   ```bash
   python app.py logs/your_log_file.log
   ```

### Command Line Options

```bash
# Use custom threshold for suspicious activity detection
python app.py --threshold 20 logs/your_log_file.log
# or
python app.py -t 20 logs/your_log_file.log

# View help
python app.py --help
```

### Log File Format

The analyzer expects log entries in the following format:
```
SRC=<source_ip> DST=<destination_ip> PROTO=<protocol> SPT=<source_port> DPT=<destination_port>
```

Example log entry:
```
SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=80
```

## Output

The analyzer generates:

1. **Console Output**:
   - Summary statistics
   - Top source IPs, destination ports, and protocols
   - Suspicious activity report

2. **Files**:
   - `firewall_analysis.png`: Visualizations of top offenders
   - `logs/parsed_output.csv`: Full parsed log data

## Suspicious Activity Detection

The analyzer looks for:
- IPs making many requests (configurable threshold)
- Connections to sensitive ports (22/SSH, 23/Telnet, 3389/RDP, etc.)
- Unusual protocols (anything other than TCP/UDP)

## Example

```bash
# Analyze logs with default settings
python app.py logs/firewall.log

# Analyze logs with custom threshold
python app.py -t 50 logs/firewall.log
```

## Requirements

- Python 3.6+
- pandas
- matplotlib

## Implementation Guide for Home Labs & Small Networks

### Setting Up Log Collection

1. **For pfSense/OPNsense Firewalls**:
   ```bash
   # Enable logging in the firewall settings
   # Navigate to: Status > System Logs > Settings
   # Enable logging and set the log format to match our parser
   ```

2. **For Linux-based Firewalls (iptables/ufw)**:
   ```bash
   # Add logging rules to iptables
   sudo iptables -A INPUT -j LOG --log-prefix "FWLOG: "
   
   # Configure rsyslog to format logs
   sudo nano /etc/rsyslog.d/iptables.conf
   # Add:
   :msg, contains, "FWLOG:" -/var/log/iptables.log
   ```

3. **For Windows Firewall**:
   - Enable logging in Windows Defender Firewall with Advanced Security
   - Configure log format to include source/destination IPs and ports

### Automated Log Analysis

1. **Create a Log Rotation Script**:
   ```bash
   #!/bin/bash
   # rotate_logs.sh
   LOG_DIR="/path/to/logs"
   ANALYSIS_DIR="/path/to/firewall_log_analyzer/logs"
   
   # Copy and rotate logs
   cp $LOG_DIR/firewall.log $ANALYSIS_DIR/firewall_$(date +%Y%m%d).log
   
   # Run analysis
   cd /path/to/firewall_log_analyzer
   python app.py $ANALYSIS_DIR/firewall_$(date +%Y%m%d).log
   ```

2. **Set Up Cron Job for Daily Analysis**:
   ```bash
   # Edit crontab
   crontab -e
   
   # Add this line to run daily at midnight
   0 0 * * * /path/to/rotate_logs.sh
   ```

### Monitoring and Alerts

1. **Set Up Email Notifications**:
   ```python
   # Add to app.py
   import smtplib
   from email.mime.text import MIMEText
   
   def send_alert(subject, body):
       msg = MIMEText(body)
       msg['Subject'] = subject
       msg['From'] = 'your-email@example.com'
       msg['To'] = 'admin@example.com'
       
       with smtplib.SMTP('smtp.server.com', 587) as server:
           server.starttls()
           server.login('username', 'password')
           server.send_message(msg)
   ```

2. **Configure Alert Thresholds**:
   - Modify the `request_threshold` based on your network's normal traffic patterns
   - Add custom sensitive ports based on your services
   - Set up alerts for specific IP ranges or patterns

### Best Practices

1. **Log Retention**:
   - Keep at least 30 days of logs for trend analysis
   - Compress old logs to save space
   - Consider using a log management system for larger deployments

2. **Security Considerations**:
   - Store logs in a secure location
   - Restrict access to log files
   - Use secure protocols for log transfer
   - Regularly review and update detection rules

3. **Performance Optimization**:
   - For large log files, consider splitting analysis into chunks
   - Schedule analysis during off-peak hours
   - Use a dedicated machine for log analysis if possible

### Example Home Lab Setup

```bash
# Directory structure
/home/analytics/
├── firewall_log_analyzer/
│   ├── app.py
│   ├── src/
│   └── logs/
└── scripts/
    └── rotate_logs.sh

# Sample crontab entry
0 */4 * * * /home/analytics/scripts/rotate_logs.sh >> /var/log/firewall_analysis.log 2>&1
```


