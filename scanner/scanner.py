import nmap
import requests
import ipaddress

# Define targets and receiver URL
# Define targets, which can be either a single IP address or a CIDR block
TARGET_INPUT = "127.0.0.1"  # Replace with your input (e.g., "127.0.0.1" or "127.0.0.0/24")


# Check if the input is a CIDR block or a single IP address
try:
    network = ipaddress.ip_network(TARGET_INPUT, strict=False)
    TARGETS = [str(ip) for ip in network]
except ValueError:
    # If it's not a valid CIDR block, treat it as a single IP address
    TARGETS = [TARGET_INPUT]

# Uncomment to use for local testing
# RECEIVER_URL = "http://127.0.0.1:5001/report"

# Uncomment to use for Docker container
RECEIVER_URL = "http://receiver:5001/report"

# Port severity classification
SEVERITY_LEVELS = {
    "critical": [22, 23, 445, 3389], # Ports commonly targeted by attackers (e.g., 22, 23, 445, 3389).
    "high": [80, 443, 3306, 5432], # Common services with potential security concerns (e.g., 80, 443, 3306, 5432).
    "medium": [25, 110, 139, 8080], # Other known services (e.g., 25, 110, 139, 8080).
}

def classify_port(port):
    """Classifies the port based on predefined severity levels."""
    for severity, ports in SEVERITY_LEVELS.items():
        if port in ports:
            return severity
    return "low"

def classify_host_severity(open_ports):
    """Classifies the host's overall severity based on open ports."""
    severity_order = ["critical", "high", "medium", "low"]
    # This is to keep track of the highest severity found
    highest_severity = "low"
    
    # Iterate over open ports and update highest_severity if needed
    for proto in open_ports:
        for port_info in open_ports[proto]:
            severity = port_info.get("severity", "low")
            if severity in severity_order:
                # Update highest_severity if the current severity is higher
                if severity_order.index(severity) < severity_order.index(highest_severity):
                    highest_severity = severity
    
    return highest_severity

def scan_host(host):
    """Scans a given host for open TCP and UDP ports using nmap."""
    nm = nmap.PortScanner()
    try:
        # Perform the scan
        nm.scan(host, arguments="-p 22,23,445,3389,80,443,3306,5432,25,110,139,8080 -sS -sU")  # Scan specified TCP and UDP ports

        # Check if the scan results contain the host
        if host not in nm.all_hosts():
            print(f"Host {host} is down or not reachable.")
            return {"tcp": [], "udp": []}, "low"

        # Initialize a dictionary to store open ports
        open_ports = {"tcp": [], "udp": []}

        # Iterate over scanned protocols and ports
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                # Classify the port and add it to the open_ports list
                port_info = {"port": port, "severity": classify_port(port)}
                open_ports[proto].append(port_info)

        # Calculate the host severity based on open ports
        host_severity = classify_host_severity(open_ports)

        return open_ports, host_severity

    except Exception as e:
        print(f"Error scanning host {host}: {e}")
        return {"tcp": [], "udp": []}, "low"

def send_results(host, open_ports, host_severity):
    """Sends scan results to the receiver server."""
    payload = {
        "host": host,
        "severity": host_severity,
        "open_ports": open_ports
    }

    headers = {
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(RECEIVER_URL, json=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            print("Results sent successfully!")
        else:
            print(f"Failed to send results: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending results: {e}")

if __name__ == "__main__":
    # Scan each target and send the results to the receiver
    for target in TARGETS:
        results, host_severity = scan_host(target)
        if results["tcp"] or results["udp"]:
            send_results(target, results, host_severity)