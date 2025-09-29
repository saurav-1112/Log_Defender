import logging

def configure_logger():
    logging.basicConfig(
        filename='keylogger_detection.log',
        level=logging.INFO,
        format='%(asctime)s - %(message)s'
    )
    logging.info("Logger configured.")
