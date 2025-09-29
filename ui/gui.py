import sys
import os
import io
import datetime
import subprocess
import threading

import tkinter as tk
from tkinter import messagebox
import sqlite3
import customtkinter as ctk
import psutil 
from pprint import pformat
import yaml

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import custom modules
from main import detect_keyloggers, scanning_files

from core.file_scanner import scan_single_file
from core.remote_connection_detector import detect_remote_connections

from utils.network_blocker import block_suspicious_ips  # Adjust this import path accordingly
from utils.ip_scanner import get_all_ips
from utils.dblogs import insert_log


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

#! Database Integration
db_path = 'logs.db'
messg = "Blocked by user"

# IP Logging in Database
def insert_ip_address(ip_address, messg):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # current timestamp to string format
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # IP address, timestamp, and message into the database
        level = "WARN"
        cursor.execute("INSERT INTO network_ip (timestamp, level, message, source_ip) VALUES (?, ?, ?)", (timestamp,level, messg,ip_address))
        
        conn.commit()
        conn.close()
        
        messagebox.showinfo("Success", f"IP Address {ip_address} added successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to add IP Address: {str(e)}")

# IP input and submission
def submit_ip_address(ip_entry):
    ip_address = ip_entry.get()
    if ip_address:
        insert_ip_address(ip_address, messg)
    else:
        messagebox.showwarning("Input Error", "Please enter a valid IP address.")


# --- main app class ---
class KeyloggerDetectApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("LogDefender Application")
        self.geometry("1000x600")
        self.resizable(False, False)

        # ?Heading
        self.label = ctk.CTkLabel(self, text="Keylogger Detection Status", font=("Helvetica", 20))
        self.label.pack(pady=20)

        self.textbox = ctk.CTkTextbox(self, width=550, height=250)
        self.textbox.pack(pady=10)

        # ?File Input
        label = ctk.CTkLabel(self, text="Enter File Name or Path:")
        label.pack(pady=10)

        self.file_input = ctk.CTkEntry(self, width=300)
        self.file_input.pack(pady=10)

        # ?frame to hold both buttons and labels centered
        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.pack(pady=20, anchor="center")

        # ?Scan Button
        self.start_button = ctk.CTkButton(self.button_frame, text="Start Scan", command=self.run_scan_thread)
        self.start_button.pack(side="left", padx=10)

        # ?File Scan
        self.scan_button = ctk.CTkButton(self.button_frame, text="Scan File", command=self.scan_file_thread)
        self.scan_button.pack(side="left", padx=10)

        # ?Network Detector
        self.clear_logs_button = ctk.CTkButton(self.button_frame, text="Detect IPs", command=self.scan_network_ip)
        self.clear_logs_button.pack(side="left", padx=10)

        self.status = ctk.CTkLabel(self, text="")
        self.status.pack(pady=5)

        # ?Add IP Address
        self.add_ip_button = ctk.CTkButton(self.button_frame, text="Add IP Address", command=self.open_ip_input_window)
        self.add_ip_button.pack(side="left", padx=10)

        # ?Block IP Address
        self.clear_logs_button = ctk.CTkButton(self.button_frame, text="Block Packets", command=self.block_ips_thread)
        self.clear_logs_button.pack(side="left", padx=10)

        self.logs_button = ctk.CTkButton(self.button_frame, text="Logs", command=self.open_logs)
        self.logs_button.pack(side="left", padx=10)


    # --- Threads ---
    def run_scan_thread(self):
        threading.Thread(target=self.run_scan, daemon=True).start()

    def scan_file_thread(self):
        threading.Thread(target=self.scan_file, daemon=True).start()
    
    def scan_network_ip(self):
        threading.Thread(target=self.scan_net_ip, daemon=True).start()
    
    def block_ips_thread(self):
        threading.Thread(target=self.block_ips, daemon=True).start()


    # --- Functions ---
    def run_scan(self):
        self.after(0, lambda: self.status.configure(text="Scanning...", text_color="orange"))
        self.textbox.delete("0.0", "end")

        import sys
        output = io.StringIO()
        sys.stdout = output

        try:
            insert_log("INFO", "Keylogger Scan Start", "N/A")
            detect_keyloggers()
        except Exception as e:
            insert_log("ERROR", f"Error during scan: {str(e)}","N/A")

        sys.stdout = sys.__stdout__

        result = output.getvalue()
        self.after(0, lambda: self.textbox.insert("0.0", result))
        self.after(0, lambda: self.status.configure(text="Scan Complete!", text_color="green"))
    
    def scan_file(self):
        self.after(0, lambda: self.status.configure(text="Scanning File...", text_color="orange"))
        self.textbox.delete("0.0", "end")

        file_name = self.file_input.get()
        print(f"File Name/Path entered: {file_name}")

        output = io.StringIO()
        sys.stdout = output

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

        try:
            #! Hardcoded configuration values
            api_config = load_config('config.yaml')
            hashes_files=load_known_hashes('data/known_hashes.yaml')
            if api_config:
                VIRUS_TOTAL_API_KEY=api_config['virus_total_api_key']
            if hashes_files:
                KNOWN_HASHES = hashes_files

            insert_log("INFO","Scanning file",file_name)
            
            suspicious = scan_single_file(file_name, KNOWN_HASHES, VIRUS_TOTAL_API_KEY)
            if suspicious:
                print(f"Suspicious File Detected: {suspicious}")
                insert_log("WARN", "Suspisous File Detected", file_name)
                # insert_log("Threat Found File Scan Complete", f"File scan completed for: {file_name}")
                from utils.email_sender import send_email
                subject = "🚨 SCRAMBLE, SCRAMBLE, SCRAMBLE Threat Detected"
                body = f"""
                    🚨 Threat Alert: Suspicious File Detected
                    Details:
                    ---------
                    File Name : {file_name}
                    Location     : {file_name}
                    Action       : Recommended to Delete the File and perform a full system scan.

                    This is an automated alert from LogDefender.
                    """
                send_email(subject=subject, body=body)
                # config_path=config.yaml
                # config = load_config(config_path)
                # sender_email = config['email']['sender']
                # password = config['email']['password']
                # receiver_email = config['email']['receiver']
                # print(f"[DEBUG] Loaded config: Sender={sender_email}, Receiver={receiver_email}")
                # print(f"[DEBUG] Subject: {subject}")
                # print(f"[DEBUG] Body Preview:\n{body[:100]}")
            else:
                print("No threats found in the selected file.")
                insert_log("INFO", "No Threat File Found", file_name)
        except Exception as e:
            insert_log("ERROR", f"Error scanning file {file_name}: {str(e)}","N/A")

        sys.stdout = sys.__stdout__

        result = output.getvalue()
        self.after(0, lambda: self.textbox.insert("0.0", result))
        self.after(0, lambda: self.status.configure(text="Scan Complete!", text_color="green"))

    def open_ip_input_window(self):
        self.ip_window = tk.Toplevel(self)
        self.ip_window.title("Enter IP Address")
        self.ip_window.geometry("300x150")
        
        ip_label = tk.Label(self.ip_window, text="Enter IP Address:")
        ip_label.pack(pady=10)
        
        self.ip_entry = tk.Entry(self.ip_window, width=30)
        self.ip_entry.pack(pady=10)

        submit_button = tk.Button(self.ip_window, text="Submit", command=lambda: submit_ip_address(self.ip_entry))
        submit_button.pack(pady=10)

   
        try:
            # Database connection
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Fetching all IPs from the network_ip
            cursor.execute("SELECT net_ip FROM network_ip")
            ips = cursor.fetchall()
            conn.close()

            if not ips:
                print("No suspicious IPs found in the database.")
                return

            # block IPs using iptables
            for ip_tuple in ips:
                ip = ip_tuple[0]

                # Block incoming and outgoing traffic for the IP
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=False)
                subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=False)
                print(f"Blocked IP: {ip}")

        except sqlite3.Error as e:
            print(f"[DB Error] {e}")
        except Exception as ex:
            print(f"[Error] {ex}")

    
        try:
            # Connecting the database and fetch suspicious IPs
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT net_ip FROM network_ip")
            ips = [row[0] for row in cursor.fetchall()]
            conn.close()

            if not ips:
                print("No suspicious IPs found.")
                return

            # Use ufw to block the IPs
            for ip in ips:
                # Block incoming from IP
                subprocess.run(["sudo", "ufw", "deny", "from", ip], check=False)
                # Block outgoing to IP
                subprocess.run(["sudo", "ufw", "deny", "to", ip], check=False)
                print(f"Blocked IP: {ip} using ufw.")

        except sqlite3.Error as db_err:
            print(f"[DB Error] {db_err}")
        except Exception as e:
            print(f"[Error] {e}")

    def block_ips(self):
        self.after(0, lambda: self.status.configure(text="Blocking Suspicious IPs...", text_color="orange"))
        self.textbox.delete("0.0", "end")

        import io
        import sys
        output = io.StringIO()
        sys.stdout = output

        try:
            from utils.network_blocker import block_suspicious_ips  # Adjust this import path accordingly
            block_suspicious_ips()
        except Exception as e:
            print(f"Error blocking IPs: {e}")

        sys.stdout = sys.__stdout__
        result = output.getvalue()
        self.after(0, lambda: self.textbox.insert("0.0", result))
        self.after(0, lambda: self.status.configure(text="IP Blocking Complete!", text_color="green"))

    def scan_net_ip(self):
        ip_data = get_all_ips()
        formatted = pformat(ip_data, indent=2)
        self.textbox.delete("1.0", "end")
        self.textbox.insert("1.0", formatted)

    def open_logs(self):
        try:
            dashboard_script = os.path.join(os.path.dirname(__file__), '..', 'web', 'dashboard.py')
            subprocess.run(['streamlit', 'run', dashboard_script], check=True)
            insert_log("INFO", "Logs Accessed","N/A")
        except Exception as e:
            insert_log("ERROR", f"Error opening logs dashboard: {str(e)}","N/A")


if __name__ == "__main__":
    app = KeyloggerDetectApp()
    app.mainloop()