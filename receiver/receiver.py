import json
from http.server import HTTPServer
import datetime
from RequestHandler import RequestHandler

def run_server():
    """Run the HTTP server."""
    server_address = ("0.0.0.0", 5001)
    httpd = HTTPServer(server_address, RequestHandler)
    print("Server running on port 5001...")
    httpd.serve_forever()

if __name__ == "__main__":
    # Start the server
    run_server()