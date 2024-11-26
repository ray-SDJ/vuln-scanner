import socket
import ssl
import requests
import whois
import dns.resolver
import nmap
import ipaddress
import re
import ssl
from urllib.parse import urlparse
from datetime import datetime
import concurrent.futures
import logging

class VulnerabilityScanner:
    def __init__(self, target):
        """
        Initialize the vulnerability scanner with a target
        
        Args:
            target (str): Target URL or IP address to scan
        """
        self.target = target
        self.parsed_url = urlparse(target)
        self.hostname = self.parsed_url.netloc or target
        self.ip_address = self._resolve_ip()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            filename='vulnerability_scan.log'
        )
        self.logger = logging.getLogger(__name__)

    def _resolve_ip(self):
        """
        Resolve hostname to IP address
        
        Returns:
            str: Resolved IP address
        """
        try:
            return socket.gethostbyname(self.hostname)
        except socket.gaierror:
            self.logger.error(f"Could not resolve IP for {self.hostname}")
            return None

    def ssl_certificate_check(self):
        """
        Check SSL certificate details and potential vulnerabilities
        
        Returns:
            dict: SSL certificate information and potential issues
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
                    
                    # Certificate Expiration Check
                    expiration = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiration - datetime.now()).days
                    
                    return {
                        'valid': True,
                        'issuer': dict(cert.get('issuer', {})),
                        'expiration_days': days_until_expiry,
                        'potential_issues': [
                            'Short expiration' if days_until_expiry < 30 else None
                        ]
                    }
        except Exception as e:
            self.logger.error(f"SSL Certificate Check Error: {e}")
            return {'valid': False, 'error': str(e)}

    def port_scan(self):
        """
        Perform comprehensive port scanning
        
        Returns:
            list: Open ports and potential services
        """
        try:
            nm = nmap.PortScanner()
            nm.scan(self.ip_address, arguments='-sV -sC')
            
            open_ports = []
            for proto in nm[self.ip_address].all_protocols():
                ports = nm[self.ip_address][proto].keys()
                for port in ports:
                    state = nm[self.ip_address][proto][port]['state']
                    service = nm[self.ip_address][proto][port].get('name', 'Unknown')
                    version = nm[self.ip_address][proto][port].get('version', 'Unknown')
                    
                    open_ports.append({
                        'port': port,
                        'state': state,
                        'service': service,
                        'version': version
                    })
            
            return open_ports
        except Exception as e:
            self.logger.error(f"Port Scanning Error: {e}")
            return []

    def domain_info(self):
        """
        Retrieve domain registration and DNS information
        
        Returns:
            dict: Domain registration details
        """
        try:
            domain = whois.whois(self.hostname)
            
            # DNS Record Check
            dns_records = {
                'A': [],
                'MX': [],
                'TXT': []
            }
            
            for record_type in ['A', 'MX', 'TXT']:
                try:
                    answers = dns.resolver.resolve(self.hostname, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    pass
            
            return {
                'registrar': domain.registrar,
                'creation_date': str(domain.creation_date),
                'expiration_date': str(domain.expiration_date),
                'dns_records': dns_records
            }
        except Exception as e:
            self.logger.error(f"Domain Information Retrieval Error: {e}")
            return {}

    def web_vulnerability_check(self):
        """
        Perform basic web vulnerability checks
        
        Returns:
            dict: Potential web vulnerabilities
        """
        vulnerabilities = {
            'headers_check': self._check_security_headers(),
            'potential_xss': self._check_xss_vulnerability(),
            'potential_sql_injection': self._check_sql_injection()
        }
        return vulnerabilities

    def _check_security_headers(self):
        """
        Check for important security headers
        
        Returns:
            dict: Security header analysis
        """
        try:
            response = requests.get(self.target, timeout=5)
            headers = response.headers
            
            required_headers = [
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Content-Security-Policy'
            ]
            
            missing_headers = [
                header for header in required_headers 
                if header.lower() not in map(str.lower, headers.keys())
            ]
            
            return {
                'total_headers': len(headers),
                'missing_security_headers': missing_headers
            }
        except Exception as e:
            return {'error': str(e)}

    def _check_xss_vulnerability(self):
        """
        Basic XSS vulnerability check
        
        Returns:
            list: Potential XSS vulnerabilities
        """
        xss_payloads = [
            '<script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '"><script>alert(1)</script>'
        ]
        
        vulnerabilities = []
        try:
            for payload in xss_payloads:
                response = requests.get(f"{self.target}?test={payload}", timeout=5)
                if payload in response.text:
                    vulnerabilities.append(payload)
        except Exception:
            pass
        
        return vulnerabilities

    def _check_sql_injection(self):
        """
        Basic SQL injection vulnerability check
        
        Returns:
            list: Potential SQL injection points
        """
        sql_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1 OR 1=1"
        ]
        
        vulnerabilities = []
        try:
            for payload in sql_payloads:
                response = requests.get(f"{self.target}?id={payload}", timeout=5)
                if len(response.text) != len(requests.get(self.target).text):
                    vulnerabilities.append(payload)
        except Exception:
            pass
        
        return vulnerabilities

    def comprehensive_scan(self):
        """
        Perform a comprehensive vulnerability scan
        
        Returns:
            dict: Complete vulnerability assessment
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            ssl_future = executor.submit(self.ssl_certificate_check)
            port_future = executor.submit(self.port_scan)
            domain_future = executor.submit(self.domain_info)
            web_vuln_future = executor.submit(self.web_vulnerability_check)
            
            return {
                'ssl_info': ssl_future.result(),
                'open_ports': port_future.result(),
                'domain_details': domain_future.result(),
                'web_vulnerabilities': web_vuln_future.result()
            }

def main():
    # Example usage
    target = input("Enter target URL or IP: ")
    scanner = VulnerabilityScanner(target)
    
    print("Starting Comprehensive Vulnerability Scan...")
    results = scanner.comprehensive_scan()
    
    # Pretty print results
    import json
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()

    #still need some work