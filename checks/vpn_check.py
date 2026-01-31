import psutil
import subprocess
import platform


VPN_KEYWORDS = [
    "tun", "tap", "ppp", "vpn", "wireguard", "openvpn",
    "nord", "express", "proton", "tailscale", "zerotier", "wintun"
]


def _interface_keyword_check():
    stats = psutil.net_if_stats()
    for name, st in stats.items():
        if not st.isup:
            continue
        nl = name.lower()
        if any(k in nl for k in VPN_KEYWORDS):
            return True, f"VPN-like interface up: {name}"
    return False, None


def _default_route_check():
    """
    Checks if default route points to known VPN gateways.
    Windows-only implementation (strong signal).
    """
    if platform.system().lower() != "windows":
        return False, None

    try:
        out = subprocess.check_output("route print 0.0.0.0", shell=True, text=True).lower()
        # Common VPN related route hints
        hints = ["wintun", "wireguard", "openvpn", "proton", "nord", "tap"]
        if any(h in out for h in hints):
            return True, "Default route shows VPN-related keywords"
        return False, None
    except Exception as e:
        return False, f"Route check error: {e}"


def is_vpn_active(ip_country_result=None, expected_country=None):
    """
    Returns:
      vpn_active (True/False)
      evidence list
    """
    evidence = []

    ok1, e1 = _interface_keyword_check()
    if ok1:
        evidence.append(e1)

    ok2, e2 = _default_route_check()
    if ok2:
        evidence.append(e2)

    # Country mismatch detection (if policy given)
    if ip_country_result and expected_country:
        if ip_country_result.get("success"):
            if ip_country_result.get("country") != expected_country:
                evidence.append(
                    f"Public country mismatch: {ip_country_result.get('country')} != {expected_country}"
                )

    return {
        "vpn_active": len(evidence) > 0,
        "evidence": evidence
    }
