import platform
import re
import subprocess


def wifi_scan(band: str = "") -> dict:
    """Survey nearby Wi-Fi networks in managed mode (Windows).

    Runs `netsh wlan show networks mode=bssid` and parses the visible access
    points: SSID, BSSID, signal %, channel, band, authentication and encryption.
    This is a passive managed-mode survey -- it does NOT use monitor mode (which
    Windows drivers do not expose). For monitor-mode capture / handshakes / deauth
    use the Realtek 8812AU adapter on Linux with the aircrack-ng suite.

    Args:
        band: Optional filter -- "2.4" or "5" to return only that band.

    Returns:
        dict with the networks found (each with its BSSIDs), plus counts, or an
        {"error": ...} dict.
    """
    if platform.system() != "Windows":
        return {
            "error": "wifi_scan relies on Windows netsh. On Linux, use "
            "'iw dev <if> scan' or airodump-ng (monitor mode) instead."
        }

    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"error": f"netsh failed: {exc}"}

    text = proc.stdout or ""
    if "SSID" not in text:
        return {
            "error": "no Wi-Fi interface found or no networks visible",
            "detail": text.strip()[:200] or proc.stderr.strip()[:200],
        }

    def _val(line: str) -> str:
        return line.split(":", 1)[1].strip() if ":" in line else ""

    networks: list[dict] = []
    cur: dict | None = None
    curb: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        ssid_m = re.match(r"SSID \d+\s*:\s*(.*)$", line)
        if ssid_m:
            cur = {
                "ssid": ssid_m.group(1).strip() or "<hidden>",
                "auth": "",
                "encryption": "",
                "bssids": [],
            }
            networks.append(cur)
            curb = None
            continue
        if cur is None:
            continue
        bssid_m = re.match(r"BSSID \d+\s*:\s*(.*)$", line)
        if bssid_m:
            curb = {
                "bssid": bssid_m.group(1).strip(),
                "signal": "",
                "radio": "",
                "band": "",
                "channel": "",
            }
            cur["bssids"].append(curb)
            continue
        if curb is None:  # SSID-level fields (before the first BSSID)
            if line.startswith("Authentication"):
                cur["auth"] = _val(line)
            elif line.startswith("Encryption"):
                cur["encryption"] = _val(line)
        else:  # BSSID-level fields
            if line.startswith("Signal"):
                curb["signal"] = _val(line)
            elif line.startswith("Radio type"):
                curb["radio"] = _val(line)
            elif line.startswith("Band"):
                curb["band"] = _val(line)
            elif line.startswith("Channel") and "utilization" not in line.lower():
                curb["channel"] = _val(line)

    if band:
        want = "2.4" if band.strip().startswith("2") else "5"
        networks = [n for n in networks if any(want in b["band"] for b in n["bssids"])]

    def _sig(n: dict) -> int:
        vals = [int(re.sub(r"\D", "", b["signal"]) or 0) for b in n["bssids"]]
        return max(vals) if vals else 0

    networks.sort(key=_sig, reverse=True)
    open_nets = [n["ssid"] for n in networks if "open" in n["auth"].lower()]

    return {
        "interface": "Wi-Fi",
        "networks_found": len(networks),
        "access_points": sum(len(n["bssids"]) for n in networks),
        "open_networks": open_nets,
        "networks": networks,
        "note": (
            "Managed-mode survey (no monitor mode). "
            + (
                "Open (unencrypted) networks present: " + ", ".join(open_nets)
                if open_nets
                else "No open networks seen."
            )
        ),
    }
