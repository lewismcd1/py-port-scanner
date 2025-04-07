import json
import datetime

# File to store scan results
JSON_FILE = "scan_results.json"

def save_to_json(sender_host, severity, open_ports):
    """Save the scan results to a JSON file."""
    # Create a dictionary for the new entry
    entry = {
        "sender_host": sender_host,
        "timestamp": datetime.datetime.now().isoformat(),
        "severity": severity,
        "open_ports": open_ports
    }

    try:
        # Read existing data from the file
        try:
            with open(JSON_FILE, "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            data = []

        # Append the new entry
        data.append(entry)

        # Write the updated data back to the file
        with open(JSON_FILE, "w") as file:
            json.dump(data, file, indent=4)

    except Exception as e:
        print(f"Error saving to JSON file: {e}")