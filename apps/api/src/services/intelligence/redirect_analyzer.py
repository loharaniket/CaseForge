import socket
import ipaddress
import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from urllib.parse import urlparse

class SSRFVulnerabilityException(Exception):
    pass

class SafeRedirectAnalyzer:
    MAX_REDIRECTS = 5
    TIMEOUT = 5.0

    @classmethod
    def _is_ip_safe(cls, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False
            # Explicitly check metadata IP
            if str(ip) == '169.254.169.254':
                return False
            return True
        except ValueError:
            return False

    @classmethod
    def _resolve_and_check(cls, hostname: str) -> str:
        try:
            # Check if it's already an IP
            ipaddress.ip_address(hostname)
            ip_to_check = hostname
        except ValueError:
            try:
                ip_to_check = socket.gethostbyname(hostname)
            except socket.gaierror:
                raise SSRFVulnerabilityException("DNS_RESOLUTION_FAILED")
        
        if not cls._is_ip_safe(ip_to_check):
            raise SSRFVulnerabilityException("BLOCKED_SECURITY_POLICY")
            
        return ip_to_check

    @classmethod
    async def analyze(cls, start_url: str) -> List[Dict[str, Any]]:
        chain = []
        current_url = start_url
        
        async with httpx.AsyncClient(verify=False, timeout=cls.TIMEOUT, max_redirects=0) as client:
            for step in range(cls.MAX_REDIRECTS + 1):
                parsed = urlparse(current_url)
                
                # Enforce scheme
                if parsed.scheme.lower() not in ('http', 'https'):
                    chain.append({
                        "original_url": current_url,
                        "status": "BLOCKED_SECURITY_POLICY",
                        "error": "UNSUPPORTED_PROTOCOL"
                    })
                    break
                    
                if not parsed.hostname:
                    chain.append({
                        "original_url": current_url,
                        "status": "BLOCKED_SECURITY_POLICY",
                        "error": "MALFORMED_URL"
                    })
                    break
                
                # Resolve & check IP
                try:
                    resolved_ip = cls._resolve_and_check(parsed.hostname)
                except SSRFVulnerabilityException as e:
                    chain.append({
                        "original_url": current_url,
                        "status": str(e),
                        "hostname": parsed.hostname
                    })
                    break
                
                node = {
                    "original_url": current_url,
                    "hostname": parsed.hostname,
                    "resolved_ip": resolved_ip,
                    "order": step,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                try:
                    # We use stream so we can restrict response size easily if needed,
                    # but since we don't read the body and only need headers for redirect, head/get is fine.
                    # We will use GET but not read the body fully to prevent large downloads.
                    async with client.stream('GET', current_url) as response:
                        node["status"] = response.status_code
                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get("Location")
                            if location:
                                # Handle relative redirects
                                if location.startswith('/'):
                                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                                node["redirect_url"] = location
                                chain.append(node)
                                current_url = location
                                continue
                        
                        # Not a redirect
                        node["final_url"] = str(response.url)
                        chain.append(node)
                        break
                        
                except httpx.TimeoutException:
                    node["status"] = "TIMEOUT"
                    chain.append(node)
                    break
                except httpx.RequestError as e:
                    node["status"] = "ERROR"
                    node["error"] = str(e)
                    chain.append(node)
                    break
            else:
                # Loop exhausted
                chain.append({
                    "original_url": current_url,
                    "status": "TOO_MANY_REDIRECTS"
                })
                
        return chain
