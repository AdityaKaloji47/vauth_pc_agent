import os
import platform


def is_rdp_active():
    if platform.system().lower() != "windows":
        return {"detected": False, "evidence": ["Non-Windows OS"]}

    evidence = []

    # Strongest signal
    session_name = os.environ.get("SESSIONNAME", "")
    if session_name.upper().startswith("RDP"):
        evidence.append(f"SESSIONNAME={session_name}")

    # Another useful signal
    if os.environ.get("CLIENTNAME"):
        evidence.append(f"CLIENTNAME={os.environ.get('CLIENTNAME')}")

    return {
        "detected": len(evidence) > 0,
        "evidence": evidence
    }
