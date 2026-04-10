import requests
import json
import time
import os
import re
import logging
from pathlib import Path
from typing import Dict, Optional, Union
from datetime import datetime, timedelta

class ThreatIntelProvider:
    """
    R.A.V.E.N. Threat Intelligence Provider
    Integrates with VirusTotal API v3 to enrich extracted IOCs with reputation data.
    Features: Automated caching, rate-limit handling, and artifact classification.
    """

    def __init__(self, api_key: str = "", cache_file: str = "core/vt_cache.json"):
        """
        Initializes the TI Provider.
        API Key resolution order: 
        1. Parameter -> 2. Environment Variable (VT_API_KEY) -> 3. Local key file
        """
        self.key_file = Path("core/api_key.txt")
        self.cache_file = Path(cache_file)
        self.base_url = "https://www.virustotal.com/api/v3"
        
        # API Key Resolution logic
        if not api_key:
            self.api_key = os.getenv("VT_API_KEY") or self._read_key_from_file() or ""
        else:
            self.api_key = api_key

        self.cache = self._load_cache()

    def _read_key_from_file(self) -> Optional[str]:
        """Attempts to read the API key from the local configuration file."""
        if self.key_file.exists():
            try:
                return self.key_file.read_text(encoding="utf-8").strip()
            except Exception as e:
                logging.error(f"Failed to read API key file: {e}")
        return None

    def _load_cache(self) -> Dict:
        """Loads historical analysis data from the cache file."""
        default_structure = {"ips": {}, "domains": {}, "files": {}}
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Validate cache structure
                    if not isinstance(data, dict) or "ips" not in data:
                        return default_structure
                    return data
            except (json.JSONDecodeError, IOError):
                return default_structure
        return default_structure

    def _save_cache(self):
        """Persists current analysis results to the local storage."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Cache persistence error: {e}")

    def detect_type(self, value: str) -> Optional[str]:
        """
        Heuristically determines the IOC type for correct API routing and caching.
        Returns: 'ips', 'files', 'domains', or None
        """
        val = value.strip().lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
            return "ips"
        if re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", val):
            return "files"
        if "." in val and not val.startswith(("http", "/")):
            return "domains"
        return None

    def check(self, value: str) -> Dict[str, str]:
        """
        Queries reputation data for a given IOC.
        Priority: 1. Local Cache -> 2. VirusTotal API
        """
        if not value: return {}
        
        query_val = value.strip().lower()
        ioc_category = self.detect_type(query_val)

        if not ioc_category:
            return {"status": "Undetermined", "score": "0/0", "owner": "N/A"}

        # Check local cache first to save API quota
        if query_val in self.cache.get(ioc_category, {}):
            return self.cache[ioc_category][query_val]

        if not self.api_key or len(self.api_key) < 10:
            return {"status": "API Key Missing", "score": "0/0", "owner": "N/A"}

        # VirusTotal API Request Layer
        try:
            # Route to correct VT endpoint
            vt_endpoint = "ip_addresses" if ioc_category == "ips" else ioc_category
            url = f"{self.base_url}/{vt_endpoint}/{query_val}"
            headers = {"accept": "application/json", "x-apikey": self.api_key}

            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code == 200:
                return self._parse_success(response, query_val, ioc_category)
            elif response.status_code == 404:
                return {"status": "Not Found", "score": "0/0", "owner": "VT Database"}
            elif response.status_code == 429:
                return {"status": "Quota Exceeded", "score": "0/0", "owner": "Rate Limited"}
            else:
                return {"status": f"Error {response.status_code}", "score": "0/0", "owner": "API Error"}

        except requests.exceptions.RequestException:
            return {"status": "Connection Error", "score": "0/0", "owner": "Network"}

    def _parse_success(self, response, query_val, category) -> Dict[str, str]:
        """Parses a successful API response and updates the local cache."""
        try:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})

            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 0
            
            # Determine overall threat status
            if malicious > 0:
                status = "🚨 MALICIOUS"
            elif suspicious > 0:
                status = "⚠️ SUSPICIOUS"
            else:
                status = "✅ CLEAN"

            result = {
                "status": status,
                "score": f"{malicious}/{total}",
                "owner": attributes.get('as_owner') or attributes.get('registrar') or "Unknown",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # Update cache and persist
            self.cache[category][query_val] = result
            self._save_cache()
            
            # Rate limiting for Free API (4 requests per minute)
            time.sleep(15) 
            return result
        except Exception:
            return {"status": "Data Parse Error", "score": "0/0", "owner": "N/A"}

def silent_cache_cleanup(cache_file: str = "core/vt_cache.json", expiry_days: int = 3):
    """
    Internal maintenance: Removes stale entries from the cache to ensure data freshness.
    Default expiry: 3 days.
    """
    path = Path(cache_file)
    if not path.exists(): return

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        now = datetime.now()
        has_changed = False
        refreshed_data = {"ips": {}, "domains": {}, "files": {}}

        for cat in ["ips", "domains", "files"]:
            if cat in data:
                for ioc, details in data[cat].items():
                    ts = details.get('timestamp')
                    if ts:
                        try:
                            item_time = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                            if now - item_time < timedelta(days=expiry_days):
                                refreshed_data[cat][ioc] = details
                            else:
                                has_changed = True
                        except:
                            has_changed = True
                    else:
                        has_changed = True

        if has_changed:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(refreshed_data, f, indent=4, ensure_ascii=False)
    except Exception:
        pass