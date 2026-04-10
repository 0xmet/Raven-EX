import re
import math
import logging
from typing import List, Set, Any, Dict
from collections import Counter

class DataFilter:
    """
    R.A.V.E.N. Data Filter & Noise Reduction Module
    Provides heuristic and statistical analysis to filter out benign system noise 
    and highlight potential Indicators of Compromise (IOCs).
    """

    def __init__(self):
        # 1. NOISE PATTERNS (System artifacts & common benign paths)
        self.noise_patterns = [
            r"share/bro/", r"base/protocols/", r"__load__", r"\.bif", 
            r"/usr/lib/", r"node_modules", r"system32", r"syswow64",
            r"frameworks", r"\.pyc$", r"analytics", r"telemetry",
            r"AppData/Local/Temp", r"metadata", r"manifest\.json",
            r"local/share", r"bin/sh", r"usr/bin", r"sbin/"
        ]
        
        # 2. WHITELIST (Trusted entities to reduce false positives)
        self.whitelist = {
            'google.com', 'microsoft.com', 'akamai.net', 'adobe.com', 
            'digicert.com', 'apple.com', '127.0.0.1', '0.0.0.0',
            'amazontrust.com', 'cloudflare.com', 'windowsupdate.com',
            'github.com', 'ubuntu.com', 'debian.org', 'android.com'
        }

        # 3. ATTACK SIGNATURES (Common adversary techniques/keywords)
        self.attack_signatures = [
            r"eval\(", r"base64", r"invoke-", r"iex", r"downloadstring",
            r"http://\d{1,3}\.", r"\\x[0-9a-f]{2}", r"temp/.*\.exe",
            r"bypass", r"noprofile", r"hidden", r"encodedcommand"
        ]

    def _get_shannon_entropy(self, data: str) -> float:
        """
        Calculates the Shannon Entropy of a string to detect potential obfuscation or encryption.
        """
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        probabilities = [count / length for count in Counter(data).values()]
        for p in probabilities:
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _is_noise(self, text: str) -> bool:
        """Checks if the text matches common noise patterns."""
        return any(re.search(p, text, re.IGNORECASE) for p in self.noise_patterns)

    def _is_whitelisted(self, text: str) -> bool:
        """Checks if the text contains whitelisted domains or IPs."""
        low_text = text.lower()
        return any(white in low_text for white in self.whitelist)

    def clean(self, category: str, data_list: List[Any]) -> List[str]:
        """
        Filters and sanitizes extracted data based on its category.
        Employs multi-stage validation: Whitelisting -> Noise Filtering -> Heuristic Analysis.
        """
        if not data_list:
            return []
        
        final_gate: Set[str] = set()
        for item in data_list:
            # Handle potential nested structures from regex findall
            raw = str(item[0] if isinstance(item, (list, tuple)) and item else item)
            raw = raw.strip().strip("'\"")
            val = raw.lower()

            # STAGE 1: Immediate Exclusion
            if self._is_whitelisted(val) or len(raw) < 4:
                continue

            # Bypass noise filter for critical categories
            if category not in ["command_lines", "processes"]:
                if self._is_noise(val):
                    continue

            # STAGE 2: Category-Specific Validation
            if category == "ip_addresses":
                # Exclude local and broadcast ranges
                if val.startswith(("127.", "0.", "255.", "192.168.", "10.", "172.16.")):
                    continue
                final_gate.add(raw)

            elif category == "domains":
                # Basic domain validation logic
                if "." not in val or "/" in val or "\\" in val:
                    continue
                tld = val.split('.')[-1]
                if len(tld) > 10 or tld.isdigit():
                    continue
                final_gate.add(val)

            elif category == "hashes":
                # Verify standard cryptographic hash lengths
                if len(val) in [32, 40, 64, 128]:
                    final_gate.add(raw)

            elif category == "file_paths":
                # Filter out hashes misidentified as paths
                if re.match(r'^[a-f0-9]{32,64}$', val):
                    continue
                if ("/" in raw or "\\" in raw) and not self._is_noise(val):
                    final_gate.add(raw)

            elif category in ["command_lines", "processes"]:
                entropy = self._get_shannon_entropy(raw)
                has_signature = any(re.search(p, val) for p in self.attack_signatures)
                
                # Heuristic: High entropy often indicates obfuscated payloads
                if (2.2 <= entropy <= 7.5) or has_signature:
                    final_gate.add(raw)

            elif category == "urls":
                if val.startswith("http"):
                    final_gate.add(raw)
            
            else:
                final_gate.add(raw)

        return sorted(list(final_gate))