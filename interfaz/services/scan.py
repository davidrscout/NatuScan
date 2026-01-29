import os
import re
import shlex
import shutil
import subprocess
import threading
import time

try:
    import nmap
except ImportError:
    nmap = None


DEFAULT_NMAP_PATHS = [r"C:\\Program Files (x86)\\Nmap\\nmap.exe", r"C:\\Program Files\\Nmap\\nmap.exe"]
DEFAULT_SCAN_ARGS = "-Pn -sV -T4 --open"


def scan_target(
    target,
    nmap_paths=None,
    return_raw=False,
    scan_args=None,
    scan_timeout=None,
    stream_callback=None,
    stats_interval=10,
    cancel_event=None,
):
    last_error = None
    args = scan_args or DEFAULT_SCAN_ARGS
    if nmap is not None and not stream_callback and not cancel_event:
        paths = nmap_paths or DEFAULT_NMAP_PATHS
        try:
            nm = nmap.PortScanner(nmap_search_path=paths)
            try:
                nm.scan(hosts=target, arguments=args, timeout=scan_timeout)
            except TypeError:
                nm.scan(hosts=target, arguments=args)
            results = []
            if target in nm.all_hosts():
                for proto in nm[target].all_protocols():
                    for port in nm[target][proto].keys():
                        port_info = nm[target][proto][port]
                        service = port_info.get('name', '')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')
                        state = port_info.get('state', 'open')
                        ver = (product + " " + version).strip()
                        results.append({
                            "port": str(port),
                            "service": service,
                            "version": ver,
                            "state": state,
                            "proto": proto,
                        })
            if return_raw:
                try:
                    raw = nm.get_nmap_last_output()
                except Exception:
                    raw = f"nmap args: {args}\nhosts: {target}\nopen ports: {len(results)}\n"
                return results, raw
            return results
        except Exception as exc:
            last_error = exc

    return _scan_with_subprocess(
        target,
        last_error=last_error,
        return_raw=return_raw,
        scan_args=args,
        scan_timeout=scan_timeout,
        stream_callback=stream_callback,
        stats_interval=stats_interval,
        cancel_event=cancel_event,
        nmap_paths=nmap_paths,
    )


def _scan_with_subprocess(
    target,
    last_error=None,
    return_raw=False,
    scan_args=None,
    scan_timeout=None,
    stream_callback=None,
    stats_interval=10,
    cancel_event=None,
    nmap_paths=None,
):
    nmap_bin = _resolve_nmap_bin(nmap_paths)
    if not nmap_bin:
        msg = "nmap no está instalado (instala nmap)"
        if last_error:
            msg += f" | {last_error}"
        raise RuntimeError(msg)

    args = scan_args or DEFAULT_SCAN_ARGS
    if isinstance(args, (list, tuple)):
        args_list = list(args)
    else:
        args_list = shlex.split(str(args), posix=False)
    cmd = [nmap_bin, *args_list, "-oG", "-", target]
    if stream_callback and stats_interval:
        cmd = [nmap_bin, *args_list, "--stats-every", f"{stats_interval}s", "-oG", "-", target]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as exc:
        raise RuntimeError(f"Error ejecutando nmap: {exc}") from exc

    stdout_lines = []
    stderr_lines = []

    def _reader(pipe, sink, kind):
        try:
            for line in iter(pipe.readline, ""):
                sink.append(line)
                if stream_callback:
                    try:
                        stream_callback(kind, line)
                    except Exception:
                        pass
        finally:
            try:
                pipe.close()
            except Exception:
                pass

    t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_lines, "stdout"), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_lines, "stderr"), daemon=True)
    t_out.start()
    t_err.start()

    start = time.time()
    while True:
        if cancel_event and cancel_event.is_set():
            _terminate_proc(proc)
            raise RuntimeError("Escaneo cancelado")
        if scan_timeout and (time.time() - start) > scan_timeout:
            _terminate_proc(proc)
            raise RuntimeError(f"nmap timeout ({scan_timeout}s)")
        ret = proc.poll()
        if ret is not None:
            break
        time.sleep(0.1)

    t_out.join(timeout=1.0)
    t_err.join(timeout=1.0)

    output_stdout = "".join(stdout_lines)
    output_stderr = "".join(stderr_lines)
    output = output_stdout + ("\n" if output_stdout else "") + output_stderr
    if proc.returncode != 0 and "Ports:" not in output:
        raise RuntimeError(f"nmap falló: {output.strip()}")

    results = _parse_grepable_output(output_stdout)
    if return_raw:
        return results, output
    return results


def _resolve_nmap_bin(nmap_paths=None):
    nmap_bin = shutil.which("nmap")
    if nmap_bin:
        return nmap_bin
    paths = nmap_paths or DEFAULT_NMAP_PATHS
    for path in paths:
        if path and os.path.exists(path):
            return path
    return None


def _terminate_proc(proc):
    try:
        proc.terminate()
    except Exception:
        return
    try:
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


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
            version = ""
            if len(parts) >= 7:
                version = "/".join(parts[6:]).strip()
            if state not in ("open", "open|filtered"):
                continue
            results.append({
                "port": port,
                "service": service,
                "version": version,
                "state": state,
                "proto": proto,
            })
    return results
