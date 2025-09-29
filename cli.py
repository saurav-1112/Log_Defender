import psutil
import hashlib
import os
import time
from pynput.keyboard import Listener
import logging

# Configure logging
logging.basicConfig(filename='keylogger_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to detect suspicious processes by matching keywords
def detect_suspicious_processes():
    suspicious_keywords = ['keylogger', 'pynput', 'hook']  # Add more keylogger-related keywords
    detected_processes = []

    for proc in psutil.process_iter(attrs=['pid', 'name', 'exe', 'cmdline']):
        try:
            process_name = proc.info['name']
            process_path = proc.info['exe']
            process_cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

            # Check if process name contains suspicious keywords
            if any(keyword in process_name.lower() for keyword in suspicious_keywords):
                detected_processes.append((proc.info['pid'], process_name, process_path, process_cmdline))
            # Additionally check command line for suspicious behavior
            elif any(keyword in process_cmdline.lower() for keyword in suspicious_keywords):
                detected_processes.append((proc.info['pid'], process_name, process_path, process_cmdline))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return detected_processes


# Function to detect if any keyboard hooks are active (using pynput listener)
def detect_keyboard_hooks():
    try:
        with Listener(on_press=None) as listener:
            listener.join(timeout=2)  # Short timeout to detect hooks
    except Exception as e:
        logging.error(f"Error detecting keyboard hooks: {e}")
        # If an exception occurs, it may indicate a keyboard hook
        return True
    return False


# Function to scan files in a directory for known suspicious hashes
def scan_files(directory):
    known_hashes = [
        # "d41d8cd98f00b204e9800998ecf8427e"  # Example hash for testing (MD5 of an empty file)
        "443d9b240dff7abf98e3d72ed2716d31"
    ]
    suspicious_files = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()  # Using SHA-256 instead of MD5
                if file_hash in known_hashes:
                    suspicious_files.append(file_path)
            except (OSError, IOError):
                continue

    return suspicious_files


# Function to detect suspicious remote connections by checking IPs
def detect_remote_connections():
    suspicious_connections = []
    suspicious_ips = ['192.168.1.100', 'example-malicious-ip.com']  # Add known malicious IPs

    for conn in psutil.net_connections():
        if conn.raddr:
            remote_ip = conn.raddr.ip
            if remote_ip in suspicious_ips:
                suspicious_connections.append((conn.laddr, conn.raddr))

    return suspicious_connections


# Main detection function that integrates all checks
def detect_keyloggers():
    print("Detecting suspicious processes...")
    processes = detect_suspicious_processes()
    if processes:
        print(f"Suspicious processes detected: {processes}")
        logging.info(f"Suspicious processes detected: {processes}")

    print("Checking for keyboard hooks...")
    if detect_keyboard_hooks():
        print("Keyboard hook detected!")
        logging.info("Keyboard hook detected!")

    print("Scanning files for keylogger signatures...")
    # file_location = input("Enter File location: ")
    file_location = "tests/hash_test"

    files = scan_files(file_location)  # Update this with the directory you want to scan
    if files:
        print(f"Suspicious files detected: {files}")
        logging.info(f"Suspicious files detected: {files}")

    print("Detecting remote connections...")
    connections = detect_remote_connections()
    if connections:
        print(f"Suspicious remote connections detected: {connections}")
        logging.info(f"Suspicious remote connections detected: {connections}")

    if not processes and not detect_keyboard_hooks() and not files and not connections:
        print("No keylogger activity detected.")
        logging.info("No keylogger activity detected.")


# Main system monitoring loop to run detection periodically
def monitor_system():
    while True:
        detect_keyloggers()
        time.sleep(60)  # Delay in seconds between scans


if __name__ == '__main__':
    print("Starting keylogger detection...")
    logging.info("Keylogger detection started.")
    monitor_system()
