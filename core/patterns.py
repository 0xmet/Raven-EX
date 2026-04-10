import re
import base64
import logging
from typing import Dict, List, Set, Optional, Any

class IOCPatterns:
    """
    R.A.V.E.N. IOC Pattern Dictionary
    Highly optimized regex patterns for real-world threat hunting and log analysis.
    Designed to reduce noise while maintaining high recall.
    """

    @staticmethod
    def get_all_patterns(tlds: Optional[Set[str]] = None) -> Dict[str, Any]:
        """
        Returns a dictionary of compiled regex patterns for various IOC types.
        """
        # Global TLD fallback if custom set is not provided
        tld_part = r"[a-zA-Z]{2,63}"
        if tlds:
            # Sort TLDs by length descending to match '.co.uk' before '.uk'
            sorted_tlds = sorted(list(tlds), key=len, reverse=True)
            tld_part = r"(?:" + "|".join(map(re.escape, sorted_tlds)) + r")"

        patterns = {
            "timestamp": re.compile(
                r"(?:"
                r"(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)|"
                r"(?:\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})|"
                r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
                r")", 
                re.IGNORECASE
            ),
            
            "ip": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            
            "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+" + tld_part + r"\b", re.IGNORECASE),
            
            "hash_patterns": [
                (re.compile(r"\b[a-fA-F0-9]{32}\b"), "MD5"),
                (re.compile(r"\b[a-fA-F0-9]{40}\b"), "SHA-1"),
                (re.compile(r"\b[a-fA-F0-9]{64}\b"), "SHA-256"),
                (re.compile(r"\b[a-fA-F0-9]{128}\b"), "SHA-512")
            ],
            
            "url": re.compile(
                r'\b(?:http|https|ftp)://' 
                r'(?:[\w\-]+\.)*'
                r'(?:[\w\-]{2,256})\.' + tld_part + 
                r'(?:\:\d{1,5})?'
                r'(?:/[^\s\)\"\'\>]*)?',
                re.IGNORECASE
            ),
            
            "windows_path": re.compile(r"[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"),
            
            "unix_path": re.compile(r"(?:\/|~\/)(?:[\w\s\-.]+\/)*[\w\s\-.]+"),
            
            "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\." + tld_part + r"\b", re.IGNORECASE),
            
            "registry": re.compile(
                r"\bHKEY(?:_CURRENT_USER|_LOCAL_MACHINE|_CLASSES_ROOT|_USERS|_CURRENT_CONFIG)(?:\\[A-Za-z0-9_\-\s]+)+", 
                re.IGNORECASE
            ),
            
            "process": re.compile(
                r"\b[\w\-. ]+\.(exe|bat|cmd|ps1|sh|bin|com|vbs|jar|py|pl|rb|php|js|dll|sys)\b", 
                re.IGNORECASE
            ),
            
            "command_line": re.compile(
                r"(?:powershell|pwsh|cmd|bash|sh|zsh|curl|wget|python|perl|wmic|schtasks|net\s+user|reg\s+add|Invoke-WebRequest|IEX|base64|nc|ncat).*", 
                re.IGNORECASE
            ),
            
            "yara": re.compile(r"rule\s+[\w\d_-]+\s*(?::\s*[\w\d_-]+\s*)?\{[\s\S]*?\}", re.IGNORECASE)
        }
        return patterns

    @staticmethod
    def decode_base64_commands(commands: List[str]) -> List[str]:
        """
        Heuristic Base64 Decoding Engine.
        Identifies and decodes Base64 strings that contain security-relevant keywords.
        """
        decoded_results: Set[str] = set()
        critical_keywords = {
            'http', 'https', 'powershell', 'iex', 'new-object', 'net.', 
            'download', 'invoke', 'cmd', 'exec', 'base64', 'bypass', 'hidden'
        }
        
        for cmd in commands:
            # Capture potential Base64 blocks (min length 8)
            b64_matches = re.findall(r"([A-Za-z0-9+/=]{8,})", cmd)
            for b64_str in b64_matches:
                try:
                    # Fix padding if necessary
                    missing_padding = len(b64_str) % 4
                    if missing_padding:
                        b64_str += '=' * (4 - missing_padding)
                    
                    decoded_bytes = base64.b64decode(b64_str, validate=False)
                    
                    # Attempt decoding with different encodings (PowerShell uses UTF-16LE)
                    for encoding in ['utf-16le', 'utf-8']:
                        try:
                            text = decoded_bytes.decode(encoding).lower().strip()
                            # Heuristic: Is it printable and does it contain threat keywords?
                            if text.isprintable() and any(kw in text for kw in critical_keywords):
                                if len(text) > 6:
                                    decoded_results.add(text)
                                    break 
                        except (UnicodeDecodeError, ValueError):
                            continue
                except Exception:
                    continue
        return list(decoded_results)

    @staticmethod
    def clean_domains(domains: List[str], tlds: Optional[Set[str]]) -> List[str]:
        """Filters out common noise and validates domains against TLD lists."""
        cleaned: Set[str] = set()
        noise_domains = {'google.com', 'microsoft.com', 'akamai.net', 'digicert.com'}
        
        for d in domains:
            d = d.lower().strip(".- ")
            if d in noise_domains or len(d) < 4:
                continue
            
            if not tlds:
                if "." in d:
                    cleaned.add(d)
                continue
            
            tld = d.split('.')[-1]
            if tld in tlds and ".." not in d and not d.startswith("-"):
                cleaned.add(d)
        return sorted(list(cleaned))

    @staticmethod
    def clean_processes(procs: List[str]) -> List[str]:
        """Cleans process lists by filtering out misidentified URLs or domains."""
        cleaned: Set[str] = set()
        excluded_extensions = ('.com', '.org', '.net', '.gov', '.edu', '.io')
        
        for p in procs:
            proc = p.strip().strip("'\"")
            # Heuristic: If it looks like a URL or a common web domain, exclude from processes
            if not proc.lower().startswith('http') and not proc.lower().endswith(excluded_extensions):
                if len(proc) > 3:
                    cleaned.add(proc)
        return sorted(list(cleaned))