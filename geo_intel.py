"""
Geo Intelligence Module
Extracts IPs from log text and enriches with mock geolocation data.
"""

import re
import random
import ipaddress


# Mock geo database — deterministic by IP hash for consistent demo results
MOCK_GEO_DB = {
    "US": {"lat": 37.0902, "lon": -95.7129},
    "CN": {"lat": 35.8617, "lon": 104.1954},
    "RU": {"lat": 61.5240, "lon": 105.3188},
    "DE": {"lat": 51.1657, "lon": 10.4515},
    "BR": {"lat": -14.2350, "lon": -51.9253},
    "IN": {"lat": 20.5937, "lon": 78.9629},
    "FR": {"lat": 46.2276, "lon": 2.2137},
    "JP": {"lat": 36.2048, "lon": 138.2529},
    "KR": {"lat": 35.9078, "lon": 127.7669},
    "NG": {"lat": 9.0820, "lon": 8.6753},
    "IR": {"lat": 32.4279, "lon": 53.6880},
    "UA": {"lat": 48.3794, "lon": 31.1656},
    "GB": {"lat": 55.3781, "lon": -3.4360},
    "NL": {"lat": 52.1326, "lon": 5.2913},
}


def extract_ips(text):
    """Extract all valid IP addresses from text using regex."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    candidates = re.findall(ip_pattern, text)

    valid_ips = set()
    for ip_str in candidates:
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_private and not ip.is_loopback and not ip.is_reserved:
                valid_ips.add(ip_str)
        except ValueError:
            continue

    return list(valid_ips)


def enrich_ip_geo(ip_address):
    """
    Enrich an external IP with mock geolocation + risk data.
    Deterministic by IP hash for consistent demo results.
    """
    seed = sum(ord(c) for c in ip_address)
    random.seed(seed)

    countries = list(MOCK_GEO_DB.keys())
    country = random.choice(countries)
    geo = MOCK_GEO_DB[country]

    # Add slight randomization to coordinates so markers don't stack
    lat = geo["lat"] + random.uniform(-2.0, 2.0)
    lon = geo["lon"] + random.uniform(-2.0, 2.0)

    risk_levels = ["Clean", "Suspicious", "Malicious", "Unknown"]
    risk = random.choices(risk_levels, weights=[40, 25, 25, 10])[0]

    return {
        "ip": ip_address,
        "country": country,
        "lat": round(lat, 4),
        "lon": round(lon, 4),
        "risk": risk
    }


def extract_and_enrich_geo(text):
    """
    Full pipeline: extract IPs from text, enrich each with geo data.
    Returns list of geo_data dicts.
    """
    ips = extract_ips(text)
    return [enrich_ip_geo(ip) for ip in ips]
