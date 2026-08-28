import requests


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key} if api_key else {}
        self.enabled = bool(api_key)

    def check_ip(self, ip: str) -> dict:
        if not self.enabled:
            raise RuntimeError("VIRUSTOTAL_API_KEY est manquante. Configurez la variable d'environnement pour activer l'enrichissement VT.")

        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        resp = requests.get(url, headers=self.headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "raw": stats,
        }