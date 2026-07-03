import re
from bs4 import BeautifulSoup

class SecurityService:
    def __init__(self) -> None:
        pass

    def check_obfuscation(self, html_content: str) -> tuple[bool, list[str]]:
        """
        Analyze HTML and JS script blocks for common obfuscation signatures.
        Flags:
        - Dangerous functions: eval(), unescape(), String.fromCharCode()
        - Hex/Unicode encoding densities
        - Massive base64 string assignments
        """
        is_obfuscated = False
        findings = []

        if not html_content:
            return False, []

        try:
            # 1. Look for dynamic evaluation blocks in raw text
            lower_html = html_content.lower()
            
            # Match eval, unescape, fromCharCode inside script tags or generally
            script_pattern = re.compile(r'<script\b[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
            scripts = script_pattern.findall(html_content)
            
            for idx, script in enumerate(scripts):
                script_lower = script.lower()
                
                # Check dynamic/dangerous functions
                if "eval(" in script_lower or "eval (" in script_lower:
                    findings.append(f"Script block {idx+1}: dynamic execution 'eval()' detected.")
                    is_obfuscated = True
                if "unescape(" in script_lower or "unescape (" in script_lower:
                    findings.append(f"Script block {idx+1}: dynamic decoding 'unescape()' detected.")
                    is_obfuscated = True
                if "string.fromcharcode" in script_lower:
                    findings.append(f"Script block {idx+1}: character code mapping 'String.fromCharCode()' detected.")
                    is_obfuscated = True

                # Check Hex-encoded characters density (e.g. \x41, \x5A)
                hex_matches = len(re.findall(r'\\x[0-9a-fA-F]{2}', script))
                if hex_matches > 15:
                    findings.append(f"Script block {idx+1}: high density of hexadecimal character encodings ({hex_matches} matches) detected.")
                    is_obfuscated = True

                # Check long base64 inline strings
                b64_pattern = re.compile(r'"[A-Za-z0-9+/]{80,}"|\'[A-Za-z0-9+/]{80,}\'')
                b64_matches = len(b64_pattern.findall(script))
                if b64_matches > 3:
                    findings.append(f"Script block {idx+1}: high count of long inline base64 data patterns detected.")
                    is_obfuscated = True

        except Exception as e:
            findings.append(f"Error executing obfuscation scanner: {str(e)}")

        return is_obfuscated, findings

    def analyze(self, headers: dict, html_content: str, redirect_count: int = 0) -> dict:
        """
        Analyze client-side security headers and page content.
        Computes a security risk score out of 100.
        """
        normalized_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        
        # 1. Audits
        csp_present = "content-security-policy" in normalized_headers
        hsts_present = "strict-transport-security" in normalized_headers
        xfo_present = "x-frame-options" in normalized_headers

        # 2. HTML frame/iframe audit
        has_iframe = False
        if html_content and BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(html_content, "html.parser")
                if soup.find(["iframe", "frame"]):
                    has_iframe = True
            except:
                pass

        # 3. JS Obfuscation scan
        js_obfuscated, obfuscation_findings = self.check_obfuscation(html_content)

        # 4. Score Calculation (Weights out of 100 max risk)
        score = 0.0
        details = []

        if not csp_present:
            score += 20.0
            details.append("Missing Content-Security-Policy (CSP) header (-20 risk)")
        if not hsts_present:
            score += 15.0
            details.append("Missing Strict-Transport-Security (HSTS) header (-15 risk)")
        if not xfo_present:
            score += 15.0
            details.append("Missing X-Frame-Options header (-15 risk)")
        if has_iframe:
            score += 15.0
            details.append("Dangerous frames/iframes found in webpage body (-15 risk)")
        if redirect_count > 2:
            score += 15.0
            details.append(f"Elevated redirect hops detected: {redirect_count} redirects (-15 risk)")
        if js_obfuscated:
            score += 20.0
            details.append("Flagged dynamic obfuscated JavaScript execution patterns (-20 risk)")
            for finding in obfuscation_findings[:3]:
                details.append(f"  -> {finding}")

        return {
            "security_score": float(score),  # out of 100 (higher means more risk)
            "csp_present": csp_present,
            "hsts_present": hsts_present,
            "x_frame_options_present": xfo_present,
            "has_iframe": has_iframe,
            "js_obfuscated": js_obfuscated,
            "redirect_count": redirect_count,
            "security_findings": details
        }
