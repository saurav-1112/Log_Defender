import time
from main import detect_keyloggers
from main import scanning_files
from main import detect_network


def monitor_system(interval=5):
    while True:
        detect_keyloggers()
        scanning_files()
        detect_network()
        time.sleep(interval)