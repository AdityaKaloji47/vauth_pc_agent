import platform

# Windows VM detection (strong)
try:
    import wmi
except Exception:
    wmi = None


VM_KEYWORDS = [
    "vmware", "virtualbox", "vbox", "qemu", "kvm",
    "hyper-v", "microsoft corporation", "xen",
    "parallels", "bochs"
]


def is_vm_detected():
    if platform.system().lower() != "windows" or wmi is None:
        return {"detected": False, "evidence": ["WMI not available"]}

    try:
        c = wmi.WMI()

        sys_info = c.Win32_ComputerSystem()[0]
        bios = c.Win32_BIOS()[0]

        manufacturer = (sys_info.Manufacturer or "").lower()
        model = (sys_info.Model or "").lower()
        bios_version = " ".join(bios.SMBIOSBIOSVersion or []).lower() if isinstance(bios.SMBIOSBIOSVersion, list) else str(bios.SMBIOSBIOSVersion).lower()

        evidence = []

        for kw in VM_KEYWORDS:
            if kw in manufacturer or kw in model or kw in bios_version:
                evidence.append(f"Matched keyword '{kw}' in system profile")

        return {
            "detected": len(evidence) > 0,
            "manufacturer": sys_info.Manufacturer,
            "model": sys_info.Model,
            "evidence": evidence
        }

    except Exception as e:
        return {"detected": False, "evidence": [str(e)]}
