from datetime import datetime

from checks.ip_region import get_public_ip_country
from checks.vpn_check import is_vpn_active
from checks.vm_check import is_vm_detected
from checks.rdp_check import is_rdp_active


EXPECTED_COUNTRY = "India"  # change for your bank policy


def run_environment_scan():
    location = get_public_ip_country()

    vpn = is_vpn_active(ip_country_result=location, expected_country=EXPECTED_COUNTRY)
    vm = is_vm_detected()
    rdp = is_rdp_active()

    # Trust policy
    trusted = (
        location["success"]
        and location["country"] == EXPECTED_COUNTRY
        and not vpn["vpn_active"]
        and not vm["detected"]
        and not rdp["detected"]
    )

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "location": location,
        "vpn": {
            "active": vpn["vpn_active"],
            "evidence": vpn["evidence"]
        },
        "vm": {
            "detected": vm["detected"],
            "evidence": vm.get("evidence", []),
            "manufacturer": vm.get("manufacturer"),
            "model": vm.get("model")
        },
        "rdp": {
            "detected": rdp["detected"],
            "evidence": rdp.get("evidence", [])
        },
        "trusted": trusted
    }
