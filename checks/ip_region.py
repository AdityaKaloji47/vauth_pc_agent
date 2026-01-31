import requests


def get_public_ip_country():
    apis = [
        ("ipinfo", "https://ipinfo.io/json"),
        ("ipapi", "https://ipapi.co/json/"),
        ("ipwhois", "https://ipwho.is/")
    ]

    for name, url in apis:
        try:
            r = requests.get(url, timeout=5)
            data = r.json()

            # ipwho.is format
            if name == "ipwhois":
                if not data.get("success", False):
                    continue
                return {
                    "success": True,
                    "ip": data.get("ip"),
                    "country": data.get("country"),
                    "source": name
                }

            # ipinfo/ipapi format
            ip = data.get("ip")
            country = data.get("country_name") or data.get("country")
            if ip and country:
                return {
                    "success": True,
                    "ip": ip,
                    "country": country,
                    "source": name
                }

        except Exception:
            continue

    return {
        "success": False,
        "ip": None,
        "country": None,
        "source": None
    }
