from pynput.keyboard import Listener
import logging

def detect_keyboard_hooks():
    try:
        with Listener(on_press=None) as listener:
            listener.join(timeout=2)
    except Exception as e:
        logging.error(f"Error detecting keyboard hooks: {e}")
        return True
    return False
