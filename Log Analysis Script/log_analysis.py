import re
import csv
from collections import defaultdict, Counter


def read_log_file(file_path):
    """Read the log file line by line."""
    with open(file_path, 'r') as file:
        return file.readlines()

def parse_log_line(line):
    """Extract IP, endpoint, status code, and message from a log entry."""
    ip_pattern = r'^([\d\.]+)'
    endpoint_pattern = r'\"[A-Z]+ (\/[^\s]*)'
    status_code_pattern = r'\" (\d{3}) '
    message_pattern = r'"([^"]+)"$'

    ip = re.search(ip_pattern, line).group(1)
    endpoint = re.search(endpoint_pattern, line).group(1)
    status_code = re.search(status_code_pattern, line).group(1)
    message = re.search(message_pattern, line)
    message = message.group(1) if message else None

    return ip, endpoint, status_code, message

def count_requests_per_ip(log_lines):
    """Count the number of requests made by each IP address."""
    ip_counts = defaultdict(int)
    for line in log_lines:
        ip, _, _, _ = parse_log_line(line)
        ip_counts[ip] += 1
    return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))

def most_accessed_endpoint(log_lines):
    """Find the most accessed endpoint and its count."""
    endpoint_counts = Counter()
    for line in log_lines:
        _, endpoint, _, _ = parse_log_line(line)
        endpoint_counts[endpoint] += 1
    return endpoint_counts.most_common(1)[0]


def detect_suspicious_activity(log_lines, threshold=10):
    """Detect IPs with failed login attempts exceeding the threshold."""
    failed_attempts = defaultdict(int)
    for line in log_lines:
        ip, _, status_code, message = parse_log_line(line)
        if status_code == '401' or (message and 'Invalid credentials' in message):
            failed_attempts[ip] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}


def display_results(ip_counts, most_accessed, suspicious_ips):
    print("IP Address           Request Count")
    for ip, count in ip_counts.items():
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20}{count}")

def save_to_csv(ip_counts, most_accessed, suspicious_ips, file_path="log_analysis_results.csv"):
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    log_file_path = "sample.log"  # Path to your log file
    log_lines = read_log_file(log_file_path)

    # Analyze logs
    ip_counts = count_requests_per_ip(log_lines)
    most_accessed = most_accessed_endpoint(log_lines)
    suspicious_ips = detect_suspicious_activity(log_lines, threshold=5)  # Adjust threshold as needed

    # Display and save results
    display_results(ip_counts, most_accessed, suspicious_ips)
    save_to_csv(ip_counts, most_accessed, suspicious_ips)

if __name__ == "__main__":
    main()
