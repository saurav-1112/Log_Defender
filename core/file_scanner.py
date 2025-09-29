import hashlib
import os

import requests
import yaml


# ? Load Function
# ? config.yaml
def load_config(filepath):
    with open(filepath, "r") as file:
        try:
            config = yaml.safe_load(file)
            return config
        except yaml.YAMLError as e:
            print(f"Error loading YAML file: {e}")
            return None


# ? data/known_hashes.yaml
def load_known_hashes(filepath):
    with open(filepath, "r") as file:
        try:
            data = yaml.safe_load(file)
            return data.get("known_hashes", [])
        except yaml.YAMLError as e:
            print(f"Error loading YAML file: {e}")
            return []


#! Hardcoded configuration values
api_config = load_config("config.yaml")
hashes_files = load_known_hashes("data/known_hashes.yaml")

if api_config:
    VIRUS_TOTAL_API_KEY = api_config["virus_total_api_key"]

if hashes_files:
    KNOWN_HASHES = hashes_files


# ? VirusTotal check function
def check_file_virus_total(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious", 0)
            > 0
        ):
            return True
    return False


def scan_files(directory, known_hashes, api_key):
    suspicious_files = []
    # cd directory && scan all files
    for root, dirs, files in os.walk(directory):
        for file in files:
            try:
                path = os.path.join(root, file)

                # SHA-256 hash Allocations
                with open(path, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()

                # Comparing hash with known_hashes.yaml
                if file_hash in known_hashes:
                    suspicious_files.append(path)

                # Comparing hash with virustotal api
                vt_result = check_file_virus_total(file_hash, api_key)
                if vt_result:
                    suspicious_files.append(path)

            except (OSError, IOError) as e:
                print(f"Error reading file {file}: {e}")
                continue

    return suspicious_files


# !Main ui Function
def scan_single_file(file_path, known_hashes, api_key):
    suspicious_files = []

    try:
        # hash setting
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        if file_hash in known_hashes:
            suspicious_files.append(file_path)
        else:
            # Check VirusTotal
            vt_result = check_file_virus_total(file_hash, api_key)
            if vt_result:
                suspicious_files.append(file_path)

    except (OSError, IOError) as e:
        print(f"Error reading file {file_path}: {e}")

    return suspicious_files


# ? Main function #Test
def scan_files_main():
    DIRECTORY_TO_SCAN = "tests/Remote_keylogger"  # Directory to scan
    suspicious_files = scan_files(DIRECTORY_TO_SCAN, KNOWN_HASHES, VIRUS_TOTAL_API_KEY)

    # Output: suspicious files found
    print(f"Suspicious files found: {suspicious_files}")


if __name__ == "__main__":
    scan_files_main()
