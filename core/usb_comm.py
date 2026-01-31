import json
import time
import secrets
import hmac
import hashlib

import serial
import serial.tools.list_ports

from core.signer import SHARED_SECRET, hmac_sign


# ================= CONFIG =================
VAUTH_VID = 0x2E8A         # Raspberry Pi Foundation (Raspberry Pi Pico)
BAUDRATE = 115200
TIMEOUT = 3                # seconds


# ================= USB ENUMERATION =================
def get_usb_state():
    """
    Inspect all USB serial devices.

    Returns:
        {
            "vauth_port": str | None,
            "unknown_usb": bool,
            "multiple_vauth": bool
        }
    """
    vauth_ports = []
    unknown_usb = False

    for port in serial.tools.list_ports.comports():
        if port.vid == VAUTH_VID:
            vauth_ports.append(port)
        elif port.vid is not None:
            unknown_usb = True

    return {
        "vauth_port": vauth_ports[0].device if len(vauth_ports) == 1 else None,
        "unknown_usb": unknown_usb,
        "multiple_vauth": len(vauth_ports) > 1
    }


# ================= HANDSHAKE =================
def perform_vauth_handshake(port_name: str) -> bool:
    """
    Authenticate VAUTH Pico using challenge–response (HMAC).
    Transport is plain text; authentication is cryptographic.
    """
    nonce = secrets.token_hex(8)

    hello_packet = {
        "type": "HELLO",
        "nonce": nonce
    }

    try:
        with serial.Serial(port_name, BAUDRATE, timeout=TIMEOUT) as ser:
            time.sleep(1)

            # Send challenge
            ser.write((json.dumps(hello_packet) + "\n").encode())

            # Receive response
            raw = ser.readline().decode().strip()
            if not raw:
                return False

            response = json.loads(raw)

            if response.get("type") != "VAUTH_RESPONSE":
                return False

            if response.get("nonce") != nonce:
                return False

            expected_hmac = hmac.new(
                SHARED_SECRET,
                nonce.encode(),
                hashlib.sha256
            ).hexdigest()

            return hmac.compare_digest(
                expected_hmac,
                response.get("hmac", "")
            )

    except Exception:
        return False


# ================= SAFE ROUTING =================
def send_scan_to_vauth(scan_result: dict):
    """
    Send scan data ONLY to verified VAUTH Pico.

    Raises RuntimeError on ANY security violation.
    """
    state = get_usb_state()

    if state["multiple_vauth"]:
        raise RuntimeError("Multiple VAUTH devices detected")

    if state["unknown_usb"]:
        raise RuntimeError("Unknown USB device detected")

    if not state["vauth_port"]:
        raise RuntimeError("VAUTH device not connected")

    if not perform_vauth_handshake(state["vauth_port"]):
        raise RuntimeError("VAUTH handshake failed")

    payload = {
        "type": "SCAN_DATA",
        "scan": scan_result,
        "signature": hmac_sign(scan_result)
    }

    with serial.Serial(
        state["vauth_port"],
        BAUDRATE,
        timeout=TIMEOUT
    ) as ser:
        time.sleep(1)
        ser.write((json.dumps(payload) + "\n").encode())
