import platform


def resolve_hosts_path():
    return r"C:\\Windows\\System32\\drivers\\etc\\hosts" if platform.system() == "Windows" else "/etc/hosts"


def append_hosts_entry(ip, domain, hosts_path=None):
    path = hosts_path or resolve_hosts_path()
    with open(path, "a") as f:
        f.write(f"\n{ip} {domain}")
    return path
