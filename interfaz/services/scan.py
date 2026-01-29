import re
import shutil
import subprocess

try:
    import nmap
except ImportError:
    nmap = None


DEFAULT_NMAP_PATHS = [r"C:\\Program Files (x86)\\Nmap\\nmap.exe", r"C:\\Program Files\\Nmap\\nmap.exe"]


def scan_target(target, nmap_paths=None):
    last_error = None
    if nmap is not None:
        paths = nmap_paths or DEFAULT_NMAP_PATHS
        try:
            nm = nmap.PortScanner(nmap_search_path=paths)
            nm.scan(hosts=target, arguments='-Pn -sV -T4 --open')
            results = []
            if target in nm.all_hosts():
                for proto in nm[target].all_protocols():
                    for port in nm[target][proto].keys():
                        service = nm[target][proto][port].get('name', '')
                        product = nm[target][proto][port].get('product', '')
                        version = nm[target][proto][port].get('version', '')
                        ver = (product + " " + version).strip()
                        results.append({"port": str(port), "service": service, "version": ver})
            return results
        except Exception as exc:
            last_error = exc

    return _scan_with_subprocess(target, last_error=last_error)


def _scan_with_subprocess(target, last_error=None):
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        msg = "nmap no está instalado (instala nmap)"
        if last_error:
            msg += f" | {last_error}"
        raise RuntimeError(msg)

    cmd = [nmap_bin, "-Pn", "-sV", "-T4", "--open", "-oG", "-", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as exc:
        raise RuntimeError(f"Error ejecutando nmap: {exc}") from exc

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0 and "Ports:" not in output:
        raise RuntimeError(f"nmap falló: {output.strip()}")

    return _parse_grepable_output(output)


def _parse_grepable_output(text):
    results = []
    for line in text.splitlines():
        if "Ports:" not in line:
            continue
        match = re.search(r"Ports:\s*(.*)", line)
        if not match:
            continue
        ports_blob = match.group(1)
        for entry in ports_blob.split(","):
            parts = entry.strip().split("/")
            if len(parts) < 5:
                continue
            port = parts[0].strip()
            state = parts[1].strip()
            proto = parts[2].strip()
            service = parts[4].strip()
            if state != "open" or proto != "tcp":
                continue
            results.append({"port": port, "service": service, "version": ""})
    return results
