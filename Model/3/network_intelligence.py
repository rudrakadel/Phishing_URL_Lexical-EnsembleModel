
import ssl
import socket
import whois
import dns.resolver

from urllib.parse import urlparse
from datetime import datetime

class NetworkIntelligenceAnalyzer:

    def extract_domain(self, url):

        parsed = urlparse(url)

        return parsed.netloc

    def check_ssl(self, domain):

        result = {
            "ssl_valid": False,
            "issuer": None,
            "days_remaining": None
        }

        try:

            context = ssl.create_default_context()

            with socket.create_connection(
                (domain, 443),
                timeout=5
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=domain
                ) as ssock:

                    cert = ssock.getpeercert()

                    result["ssl_valid"] = True

                    issuer = dict(
                        x[0] for x in cert["issuer"]
                    )

                    result["issuer"] = issuer.get(
                        "organizationName"
                    )

                    expiry = datetime.strptime(
                        cert["notAfter"],
                        "%b %d %H:%M:%S %Y %Z"
                    )

                    result["days_remaining"] = (
                        expiry - datetime.utcnow()
                    ).days

        except:
            pass

        return result

    def analyze(self, url):

        domain = self.extract_domain(url)

        ssl_data = self.check_ssl(domain)

        return {
            "domain": domain,
            "ssl": ssl_data
        }
