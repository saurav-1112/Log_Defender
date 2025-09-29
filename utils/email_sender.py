import smtplib
import yaml
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def load_config(path="config.yaml"):
    with open(path, 'r') as file:
        return yaml.safe_load(file)

def send_email(subject, body, config_path=os.path.join(os.path.dirname(__file__), "..", "config.yaml")):
    config = load_config(config_path)
    sender_email = config['email']['sender']
    password = config['email']['password']
    receiver_email = config['email']['receiver']

    print(f"[DEBUG] Loaded config: Sender={sender_email}, Receiver={receiver_email}")
    print(f"[DEBUG] Subject: {subject}")
    print(f"[DEBUG] Body Preview:\n{body[:100]}")

    # Create email
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(message)
        print("✅ Email sent successfully.")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
    finally:
        try:
            server.quit()
        except:
            pass
