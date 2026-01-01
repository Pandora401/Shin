import shodan
import os

class IntelService:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.api = shodan.Shodan(self.api_key) if self.api_key else None

    def check_ip(self, ip_address):
        if not self.api:
            return {"error": "Shodan API key not configured"}
        
        try:
            host = self.api.host(ip_address)
            return {
                "ip": host.get('ip_str'),
                "org": host.get('org', 'n/a'),
                "os": host.get('os', 'n/a'),
                "ports": host.get('ports', []),
                "vulns": list(host.get('vulns', [])),
                "data": host.get('data', [])
            }
        except shodan.APIError as e:
            return {"error": str(e)}

intel_service = IntelService()
