import json
import datetime
from http.server import BaseHTTPRequestHandler
from utils import save_to_json

class RequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP request handler."""

    def do_POST(self):
        """Handle POST requests."""
        if self.path == "/report":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                # Parse the JSON data from the request
                data = json.loads(post_data)

                # Extract sender host from HTTP headers
                sender_host = data.get("host", "unknown")

                # Extract data from the payload
                severity = data.get("severity", "unknown")
                open_ports = data.get("open_ports", {})

                # Save the data to the JSON file
                save_to_json(sender_host, severity, open_ports)

                # Send a success response
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Report received successfully"}).encode())

            except Exception as e:
                # Handle errors
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            # Handle invalid endpoints
            self.send_response(404)
            self.end_headers()