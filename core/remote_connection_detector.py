import psutil
import sqlite3

#! Database Integration
db_path = 'logs.db'

# Function to fetch suspicious IPs from the database
def fetch_suspicious_ips():
    conn = sqlite3.connect(db_path)  # Update the path to the correct database
    cursor = conn.cursor()

    # Query to fetch all suspicious IPs from the 'suspicious_ips' table
    cursor.execute("SELECT net_ip FROM network_ip")
    suspicious_ips = [row[0] for row in cursor.fetchall()]  # Extract IP addresses
    conn.close()

    return suspicious_ips

# Function to detect remote connections
def detect_remote_connections():
    suspicious_ips = fetch_suspicious_ips()  # Fetch suspicious IPs from the database
    connections = []

    for conn in psutil.net_connections():
        if conn.raddr:
            if conn.raddr.ip in suspicious_ips:
                connections.append((conn.laddr, conn.raddr))

    return connections


# if __name__ == "__main__":
#     suspicious_connections = detect_remote_connections()
#     for conn in suspicious_connections:
#         print(f"Suspicious connection from {conn[1].ip} to local address {conn[0].ip}")
