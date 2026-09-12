import os
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# Well-known ports -> service name, used both as the default scan set and to
# label results.
_COMMON = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3000: "dev-http",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

_MAX_PORTS = 5000  # safety cap so one call can't scan the whole 65k range slowly


def _parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443', '1-1024', or space/comma mixes into a port list."""
    ports: set[int] = set()
    for chunk in spec.replace(",", " ").split():
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            try:
                a, b = int(lo), int(hi)
            except ValueError:
                continue
            ports.update(range(max(1, a), min(65535, b) + 1))
        else:
            try:
                p = int(chunk)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def port_scan(target: str, ports: str = "", timeout: float = 1.0) -> dict:
    """TCP connect-scan a host's ports (authorised targets only).

    Args:
        target: Hostname, IP, or URL (scheme/path are stripped).
        ports: Ports to scan as a list/range, e.g. "22,80,443" or "1-1024".
               Defaults to a set of common service ports when empty.
        timeout: Per-port connect timeout in seconds.

    Returns:
        dict with the resolved host/ip, the open ports and their likely service,
        and scan counts -- or an {"error": ...} dict.
    """
    if os.environ.get("SLEUTH_ALLOW_ACTIVE_SKILLS", "").strip().lower() not in (
        "1", "true", "yes", "on",
    ):
        return {"ok": False, "error": "Skill 'port_scan' is disabled. "
                "Set SLEUTH_ALLOW_ACTIVE_SKILLS=true for authorised targets only."}

    host = urlparse(target if "://" in target else "//" + target).hostname or target
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return {"error": f"could not resolve '{host}': {exc}"}

    port_list = _parse_ports(ports) if ports else sorted(_COMMON)
    if not port_list:
        return {"error": f"no valid ports parsed from '{ports}'"}
    if len(port_list) > _MAX_PORTS:
        return {"error": f"too many ports ({len(port_list)} > {_MAX_PORTS}); "
                "narrow the range."}

    def _check(port: int) -> int | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            return port if sock.connect_ex((ip, port)) == 0 else None
        except OSError:
            return None
        finally:
            sock.close()

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=min(200, len(port_list))) as pool:
        for result in pool.map(_check, port_list):
            if result is not None:
                open_ports.append(result)
    open_ports.sort()

    return {
        "host": host,
        "ip": ip,
        "ports_scanned": len(port_list),
        "open_count": len(open_ports),
        "open": [{"port": p, "service": _COMMON.get(p, "unknown")} for p in open_ports],
        "note": ("Open ports found above; closed/filtered ports are omitted."
                 if open_ports else
                 "No open ports among those scanned (host may be firewalled or "
                 "only serving on ports not in the set)."),
    }
