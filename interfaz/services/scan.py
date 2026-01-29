try:
    import nmap
except ImportError:
    nmap = None


DEFAULT_NMAP_PATHS = [r"C:\\Program Files (x86)\\Nmap\\nmap.exe", r"C:\\Program Files\\Nmap\\nmap.exe"]


def scan_target(target, nmap_paths=None):
    if nmap is None:
        raise RuntimeError("python-nmap no está instalado.")
    paths = nmap_paths or DEFAULT_NMAP_PATHS
    try:
        nm = nmap.PortScanner(nmap_search_path=paths)
    except nmap.PortScannerError as exc:
        raise RuntimeError("No se encontró nmap.exe") from exc

    nm.scan(hosts=target, arguments='-Pn -sV -T4 --open')
    results = []
    if target in nm.all_hosts():
        for proto in nm[target].all_protocols():
            for port in nm[target][proto].keys():
                service = nm[target][proto][port]['name']
                version = nm[target][proto][port]['product'] + " " + nm[target][proto][port]['version']
                results.append({"port": str(port), "service": service, "version": version})
    return results
