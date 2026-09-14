import re
from pathlib import Path


def parse_ssh_config(host_pattern=None):
    """Parse SSH config file and return matching hosts."""
    ssh_config_path = Path.home() / ".ssh" / "config"
    if not ssh_config_path.exists():
        return {}

    hosts = {}
    current_host = None

    with open(ssh_config_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.lower().startswith("host "):
                current_host = line.split()[1]
                hosts[current_host] = {}
            elif current_host and " " in line:
                key, value = line.split(None, 1)
                hosts[current_host][key.lower()] = value

    if host_pattern:
        return {k: v for k, v in hosts.items() if re.search(host_pattern, k, re.IGNORECASE)}

    return hosts


def suggest_ssh_hosts(query=""):
    """Suggest SSH hosts from config file."""
    hosts = parse_ssh_config()
    if not query:
        return list(hosts.keys())

    return [host for host in hosts.keys() if query.lower() in host.lower()]


def get_ssh_connection_string(host_config):
    """Convert SSH config to connection string."""
    hostname = host_config.get("hostname", "")
    user = host_config.get("user", "")
    port = host_config.get("port", "22")

    if user and hostname:
        conn_str = f"{user}@{hostname}"
        if port != "22":
            conn_str += f":{port}"
        return conn_str

    return None
