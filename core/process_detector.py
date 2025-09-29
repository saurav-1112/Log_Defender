import psutil
import yaml
import os


#? Load Function
#? suspicious_keywords.yaml
def load_yaml(filepath, key=None):
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return None
    try:
        with open(filepath, 'r') as file:
            data = yaml.safe_load(file)
            return data.get(key, []) if key else data
    except yaml.YAMLError as e:
        print(f"[!] Error loading YAML file: {e}")
        return None

def detect_suspicious_processes():
    
    #! Hardcoded configuration values
    suspicious_keywords = load_yaml('data/suspicious_keywords.yaml', key='keywords')
    
    # Fallback to hardcoded keywords if loading fails
    if not suspicious_keywords:
        suspicious_keywords = [
            'keylogger', 'pynput', 'hook', 'keyboard', 'capture', 'record', 'keystroke', 'listener', 'intercept',
            'grabber', 'logger', 'inputhook', 'keyhook', 'spy', 'monitor', 'screenshot', 'cliplogger', 'stealer',
            'remote', 'rat', 'inject', 'dllinject', 'persistence', 'taskhide', 'hidewindow', 'rootkit', 'backdoor',
            'malware', 'trojan', 'sniffer', 'payload', 'metasploit', 'beacon', 'c2', 'command&control', 'bindshell',
            'reverse_shell', 'mimikatz', 'credsdump', 'dump', 'scraper', 'scrape', 'exfiltrate', 'obfuscate', 'cryptor'
        ]

    detected_processes = []

    for proc in psutil.process_iter(attrs=['pid', 'name', 'exe', 'cmdline']):
        try:
            name = proc.info['name'] or ""
            path = proc.info['exe'] or ""
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

            combined_info = f"{name} {cmdline}".lower()

            if any(keyword in combined_info for keyword in suspicious_keywords):
                detected_processes.append({
                    'pid': proc.info['pid'],
                    'name': name,
                    'path': path,
                    'cmdline': cmdline
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return detected_processes
