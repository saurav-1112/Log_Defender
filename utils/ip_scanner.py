import psutil
import socket
import requests
import docker
import re

def get_all_ips():
    all_ips = {
        "system_interfaces": {},
        "docker_containers": {},
        "external_ip": None,
        "etc_hosts": []
    }

    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                all_ips["system_interfaces"][iface] = addr.address

    try:
        client = docker.from_env()
        for container in client.containers.list():
            name = container.name
            try:
                ip = container.attrs['NetworkSettings']['IPAddress']
                all_ips["docker_containers"][name] = ip
            except KeyError:
                all_ips["docker_containers"][name] = "N/A"
    except Exception as e:
        all_ips["docker_containers"] = {"error": str(e)}

    try:
        all_ips["external_ip"] = requests.get('https://api.ipify.org').text
    except Exception as e:
        all_ips["external_ip"] = f"Error: {e}"

    try:
        with open("/etc/hosts", "r") as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line.startswith("#") and line:
                    match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        all_ips["etc_hosts"].append(match.group(1))
    except Exception as e:
        all_ips["etc_hosts"] = [f"Error: {e}"]

    return all_ips
