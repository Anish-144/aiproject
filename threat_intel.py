import random
import ipaddress

def enrich_ip(ip_address):
    """
    Enriches an IP address with mock threat intelligence.
    In a real scenario, this would call an API like VirusTotal or AbuseIPDB.
    """
    try:
        # Validate IP
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private:
            return {
                "ip": ip_address,
                "country": "Internal/Private",
                "asn": "N/A",
                "reputation": "Safe (Internal)",
                "isp": "Local Network"
            }
    except ValueError:
        return {
            "ip": ip_address,
            "error": "Invalid IP Address"
        }

    # Mock Data Generation based on IP hash to be deterministic for demo
    seed =  sum(ord(c) for c in ip_address)
    random.seed(seed)

    countries = ["US", "CN", "RU", "DE", "BR", "IN", "FR", "JP"]
    asns = ["AS15169 Google LLC", "AS16509 Amazon.com", "AS4134 Chinanet", "AS20940 Akamai", "AS8075 Microsoft"]
    reputations = ["Clean", "Suspicious", "Malicious", "Unknown"]
    isps = ["Google Cloud", "Amazon AWS", "China Telecom", "Comcast", "DigitalOcean"]

    # weighted random for maliciousness
    reputation = random.choices(reputations, weights=[50, 20, 20, 10])[0]

    return {
        "ip": ip_address,
        "country": random.choice(countries),
        "asn": random.choice(asns),
        "reputation": reputation,
        "isp": random.choice(isps)
    }
