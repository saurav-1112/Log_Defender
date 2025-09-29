import sqlite3
from datetime import datetime

# Database setup
def create_db():
    conn = sqlite3.connect('logs.db')  # Creates the database file if it doesn't exist
    c = conn.cursor()
    
    # Create a table for storing logs if it doesn't already exist
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    location TEXT NOT NULL
                )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS network_ip (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    source_ip TEXT NOT NULL
                )''')
    
    conn.commit()
    conn.close()

# Function to insert logs into the database
def insert_log(level, log_message, location):
    conn = sqlite3.connect('logs.db')  # Connect to the database
    c = conn.cursor()
    
    # Get the current timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Insert log into the table
    c.execute("INSERT INTO logs (timestamp, level, message,location) VALUES (?, ?, ?, ?)",
              (timestamp, level, log_message, location))
    
    conn.commit()
    conn.close()

def db_network_ip(level, message, source_ip):
    conn = sqlite3.connect('logs.db')  # Connect to the database
    c = conn.cursor()
    
    # Get the current timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Insert log into the table
    c.execute("INSERT INTO network_ip (timestamp, level, message, source_ip) VALUES (?, ?, ?, ?)",
              (timestamp, level, message, source_ip))
    
    conn.commit()
    conn.close()

# Call this function to create the database and table when starting the application
create_db()