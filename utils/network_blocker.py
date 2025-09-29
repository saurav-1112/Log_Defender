import sqlite3
import subprocess

def block_suspicious_ips(db_path="logs.db"):
    try:
        # Connect to the database and fetch suspicious IPs
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
        # Add iptables rule to block incoming and outgoing connections to the target IP
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            print(f"Blocked all connections to/from {ip}")
            
            from utils.email_sender import send_email
            subject = "🚨 SCRAMBLE, SCRAMBLE, SCRAMBLE Threat Detected"
            body = f"""
                🚨 Threat Alert: Suspicious Remote IP Detected
                Details:
                ---------
                ip : {ip}
               
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
        
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")

    except sqlite3.Error as db_err:
        print(f"[DB Error] {db_err}")
    except Exception as e:
        print(f"[Error] {e}")
