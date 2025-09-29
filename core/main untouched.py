from utils.logger import configure_logger
from core.process_detector import detect_suspicious_processes
from core.keyboard_hook_detector import detect_keyboard_hooks
from core.file_scanner import scan_files
from core.remote_connection_detector import detect_remote_connections
import logging

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

    print("Scanning files...")
    files = scan_files("/path/to/directory")  # <-- Change this path
    if files:
        print(f"Suspicious files detected: {files}")
        logging.info(f"Suspicious files detected: {files}")

    print("Detecting remote connections...")
    connections = detect_remote_connections()
    if connections:
        print(f"Suspicious remote connections: {connections}")
        logging.info(f"Suspicious remote connections: {connections}")

    if not (processes or files or connections or detect_keyboard_hooks()):
        print("No keylogger activity detected.")
        logging.info("No keylogger activity detected.")





if __name__ == "__main__":
    configure_logger()
    print("Starting keylogger detection...")
    logging.info("Keylogger detection started.")
    from monitor import monitor_system
    monitor_system()
