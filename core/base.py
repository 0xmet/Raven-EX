import re
import logging
from pathlib import Path
from typing import Dict, List, Generator
from core.handlers import FormatHandlers
from core.patterns import IOCPatterns

class IOCExtractor:
    """
    R.A.V.E.N. Core Extraction Engine
    Handles high-performance IOC extraction from various file formats using stream processing.
    """

    def __init__(self, file_path: str):
        """
        Initializes the extractor with a target file path.
        Security: Resolves absolute path to mitigate Path Traversal risks.
        """
        self.file_path = Path(file_path).resolve()
        self.file_type = self.file_path.suffix.lower()
        
        # Initialize IOC storage with predefined categories
        self.iocs: Dict[str, List[str]] = {k: [] for k in [
            "timestamps", "ip_addresses", "domains", "hashes", "urls", 
            "file_paths", "processes", "command_lines", "decoded_commands", 
            "emails", "registry_keys", "user_agents", "yara_rules"
        ]}

    def stream_content(self) -> Generator[str, None, None]:
        """
        Memory-efficient line-by-line file reader (Generator).
        Enables processing of large-scale logs with minimal RAM footprint.
        """
        # Specialized file format handlers
        if self.file_type == '.evtx': 
            yield from FormatHandlers.process_evtx(self.file_path).splitlines()
            return
        if self.file_type in ['.pcap', '.pcapng']: 
            yield from FormatHandlers.process_pcap(self.file_path).splitlines()
            return
        if self.file_type == '.pdf': 
            yield from FormatHandlers.process_pdf(self.file_path).splitlines()
            return
        
        # Standard text-based file processing (Log, txt, csv, etc.)
        try:
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line
        except Exception as e:
            # Silently handle access errors; logging can be implemented here
            logging.error(f"Error reading file {self.file_path}: {e}")
            return

    def extract(self) -> Dict[str, List[str]]:
        """
        Primary IOC Extraction Engine. Performs stream-based analysis on the target file.
        """
        patterns = IOCPatterns.get_all_patterns()
        
        is_zeek = False
        zeek_fields = []

        for line in self.stream_content():
            if not line or not line.strip():
                continue
            
            line_strip = line.strip()

            # --- Zeek Log Detection and Processing ---
            if line_strip.startswith("#separator"):
                is_zeek = True
                continue
            if is_zeek and line_strip.startswith("#fields"):
                zeek_fields = line_strip.split('\t')[1:]
                continue
            if is_zeek and line_strip.startswith("#"):
                continue

            if is_zeek and zeek_fields:
                self._parse_zeek_line(line_strip, zeek_fields)
            else:
                # --- Standard Log Processing ---
                self._parse_standard_line(line_strip, patterns)

        # Post-processing: Deduplication and Data Sanitization
        self._finalize_results()
        return self.iocs

    def _parse_standard_line(self, line: str, p: Dict):
        """
        Performs regex-based pattern matching on a single line of text.
        """
        lower_line = line.lower()
        
        # 1. Command Line Activity Detection
        cmd_keywords = ["powershell", "cmd.exe", "bash", "nc ", "iex", "encodedcommand"]
        if any(cmd in lower_line for cmd in cmd_keywords):
            self.iocs["command_lines"].append(line)
        elif re.search(r'[\-|/][a-zA-Z]+\s+.*[|>|&]', line):
            self.iocs["command_lines"].append(line)

        # 2. Automated Pattern Matching
        self.iocs["ip_addresses"].extend(p["ip"].findall(line))
        self.iocs["domains"].extend(p["domain"].findall(line))
        self.iocs["urls"].extend(p["url"].findall(line))
        
        for pat, _ in p["hash_patterns"]:
            self.iocs["hashes"].extend(re.findall(pat, line))
        
        self.iocs["file_paths"].extend(p["windows_path"].findall(line))
        self.iocs["file_paths"].extend(p["unix_path"].findall(line))

    def _parse_zeek_line(self, line: str, fields: List[str]):
        """
        Intelligently maps Zeek log columns to IOC categories.
        """
        values = line.split('\t')
        if len(values) != len(fields): 
            return
        
        for i, val in enumerate(values):
            if val in ["-", "(empty)"]: 
                continue
            field_name = fields[i].lower()
            
            if any(x in field_name for x in ["addr", "orig_h", "resp_h"]):
                self.iocs["ip_addresses"].append(val)
            elif any(h in field_name for h in ["md5", "sha1", "sha256"]):
                self.iocs["hashes"].append(val)
            elif any(d in field_name for d in ["host", "query", "domain"]):
                self.iocs["domains"].append(val)
            elif any(f in field_name for f in ["path", "filename", "name"]):
                # Ensure filename is not a hash incorrectly classified by Zeek
                if not re.match(r'^[a-fA-F0-9]{32,64}$', val):
                    self.iocs["file_paths"].append(val)

    def _finalize_results(self):
        """
        Sanitizes, deduplicates, and sorts the extracted IOC results.
        """
        for key in self.iocs:
            unique_items = set()
            for item in self.iocs[key]:
                val = str(item).strip().strip("'\"")
                
                # Basic noise filtering
                if len(val) < 4: 
                    continue
                # Prevent hashes from appearing in file_paths
                if key == "file_paths" and re.match(r'^[a-fA-F0-9]{32,64}$', val): 
                    continue
                
                unique_items.add(val)
            
            self.iocs[key] = sorted(list(unique_items))