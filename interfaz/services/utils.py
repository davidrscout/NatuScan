import platform
import shutil
import subprocess


def resolve_hosts_path():
    return r"C:\\Windows\\System32\\drivers\\etc\\hosts" if platform.system() == "Windows" else "/etc/hosts"


def append_hosts_entry(ip, domain, hosts_path=None):
    path = hosts_path or resolve_hosts_path()
    try:
        with open(path, "a") as f:
            f.write(f"\n{ip} {domain}")
        return path
    except PermissionError as exc:
        if platform.system() != "Windows":
            _try_pkexec_append(path, ip, domain)
            return path
        raise exc


def _try_pkexec_append(path, ip, domain):
    pkexec = shutil.which("pkexec")
    if not pkexec:
        raise PermissionError(f"Permisos insuficientes para {path}")
    line = f"{ip} {domain}\n"
    cmd = [pkexec, "tee", "-a", path]
    subprocess.run(cmd, input=line, text=True, check=True, capture_output=True)
