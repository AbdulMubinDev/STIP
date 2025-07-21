import re
import json
from typing import Dict, List, Set
from urllib.parse import urlparse

class IOCParser:
    """
    IOC (Indicators of Compromise) Parser
    Extracts IP addresses, hashes, URLs, and domains from text
    """
    
    def __init__(self):
        # IP address pattern (IPv4)
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # MD5 hash pattern (32 hex characters)
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        
        # SHA1 hash pattern (40 hex characters)
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        
        # SHA256 hash pattern (64 hex characters)
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        
        # URL pattern
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?',
            re.IGNORECASE
        )
        
        # Domain pattern
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
    
    def extract_ips(self, text: str) -> Set[str]:
        """Extract IP addresses from text"""
        ips = set(self.ip_pattern.findall(text))
        # Filter out common false positives (version numbers, etc.)
        filtered_ips = set()
        for ip in ips:
            parts = ip.split('.')
            # Basic validation - avoid obvious version numbers
            if not (parts[0] == '0' or (parts[0] == '1' and parts[1] == '0')):
                filtered_ips.add(ip)
        return filtered_ips
    
    def extract_hashes(self, text: str) -> Dict[str, Set[str]]:
        """Extract various hash types from text"""
        hashes = {
            'md5': set(self.md5_pattern.findall(text)),
            'sha1': set(self.sha1_pattern.findall(text)),
            'sha256': set(self.sha256_pattern.findall(text))
        }
        return hashes
    
    def extract_urls(self, text: str) -> Set[str]:
        """Extract URLs from text"""
        return set(self.url_pattern.findall(text))
    
    def extract_domains(self, text: str) -> Set[str]:
        """Extract domains from text (excluding URLs)"""
        domains = set(self.domain_pattern.findall(text))
        # Remove domains that are part of URLs
        urls = self.extract_urls(text)
        url_domains = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    url_domains.add(parsed.netloc)
            except:
                continue
        
        # Filter out common false positives and URL domains
        filtered_domains = set()
        common_extensions = {'.txt', '.log', '.exe', '.dll', '.bat', '.cmd', '.ps1'}
        
        for domain in domains:
            # Skip if it's part of a URL
            if domain in url_domains:
                continue
            # Skip if it looks like a file extension
            if any(domain.endswith(ext) for ext in common_extensions):
                continue
            # Skip obvious false positives
            if not ('.' in domain and len(domain) > 3):
                continue
            filtered_domains.add(domain)
        
        return filtered_domains
    
    def extract_iocs(self, text: str) -> Dict:
        """
        Extract all IOCs from text
        Returns a dictionary with categorized IOCs
        """
        iocs = {
            'ips': list(self.extract_ips(text)),
            'hashes': {k: list(v) for k, v in self.extract_hashes(text).items()},
            'urls': list(self.extract_urls(text)),
            'domains': list(self.extract_domains(text)),
            'total_count': 0
        }
        
        # Calculate total count
        iocs['total_count'] = (
            len(iocs['ips']) +
            sum(len(v) for v in iocs['hashes'].values()) +
            len(iocs['urls']) +
            len(iocs['domains'])
        )
        
        return iocs