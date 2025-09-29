from utils.logger import configure_logger
from core.process_detector import detect_suspicious_processes
from core.file_scanner import scan_files
from core.keyboard_hook_detector import detect_keyboard_hooks
from core.remote_connection_detector import detect_remote_connections
from utils.dblogs import insert_log
from utils.email_sender import send_email

import logging
import yaml


def detect_keyloggers():
    """Detect suspicious processes and keyboard hooks."""
    print("Detecting suspicious processes...")
    processes = detect_suspicious_processes()
    if processes:
        print(f"Suspicious processes detected: {processes}")
        logging.info(f"Suspicious processes detected: {processes}")
        from utils.dblogs import insert_log
        insert_log("WARN", "Keylogger Detected.", processes)
        from utils.email_sender import send_email
        subject = "SCRAMBLE, SCRAMBLE, SCRAMBLE Threat Detected"
        body = f"""
            🚨 Threat Alert: Keylogger Detected

            Details:
            ---------
            Process Name : {processes}
            Action       : Recommended to terminate the process and perform a full system scan.

            This is an automated alert from LogDefender.
            """
        send_email(subject=subject, body=body)

    print("Checking for keyboard hooks...")
    if detect_keyboard_hooks():
        print("Keyboard hook detected!")
        logging.info("Keyboard hook detected!")
        insert_log("WARN", "Keylogger Hook Detected.","N/A")
        from utils.email_sender import send_email
        subject = "SCRAMBLE, SCRAMBLE, SCRAMBLE Threat Detected"
        body = f"""
            🚨 Threat Alert: Keylogger Detected

            Details:
            ---------
            Process Name : {processes}
            Action       : Recommended to terminate the process and perform a full system scan.

            This is an automated alert from LogDefender.
            """
        send_email(subject=subject, body=body)
    return processes

#? Load Function
#? config.yaml
def load_config(filepath):
    with open(filepath, 'r') as file:
        try:
            config = yaml.safe_load(file)
            return config
        except yaml.YAMLError as e:
            print(f"Error loading YAML file: {e}")
            return None

#? data/known_hashes.yaml
def load_known_hashes(filepath):
    with open(filepath, 'r') as file:
        try:
            data = yaml.safe_load(file)
            return data.get('known_hashes', [])
        except yaml.YAMLError as e:
            print(f"Error loading YAML file: {e}")
            return []

#! Hardcoded configuration values
api_config = load_config('config.yaml')
hashes_files=load_known_hashes('data/known_hashes.yaml')

if api_config:
    VIRUS_TOTAL_API_KEY=api_config['virus_total_api_key']

if hashes_files:
    KNOWN_HASHES = hashes_files

def scanning_files(directory_path):
    suspicious_files = scan_files(directory_path, KNOWN_HASHES, VIRUS_TOTAL_API_KEY)
    if suspicious_files:
        print(f"Suspicious Files Detected: {suspicious_files}")
    else:
        print("No suspicious files found.")
    return suspicious_files, "Scan Completed"


def detect_network(processes, files):
    """Detect suspicious remote connections."""
    print("Detecting remote connections...")
    connections = detect_remote_connections()
    if connections:
        print(f"Suspicious remote connections: {connections}")
        logging.info(f"Suspicious remote connections: {connections}")
        subject = "SCRAMBLE, SCRAMBLE, SCRAMBLE Threat Detected"
        body = f"""
            🚨 Threat Alert: Suspicious Remote IP Address Detected

            Details:
            ---------
            Connection Name : {connections}

            This is an automated alert from LogDefender.
            """
        send_email(subject=subject, body=body)

    if not (processes or files or connections or detect_keyboard_hooks()):
        print("No keylogger activity detected.")
        logging.info("No keylogger activity detected.")

def monitor_system():
    """Run the system monitoring loop."""
    directory = "/path/to/directory" 
    while True:
        processes = detect_keyloggers()
        files, scan_msg = scanning_files(directory)
        detect_network(processes, files)

if __name__ == "__main__":
    configure_logger()  # Configure logging before starting detection
    print("Starting keylogger detection...")
    logging.info("Keylogger detection started.")
    monitor_system()
