import platform
import logging
from typing import List, Union, Optional
from pathlib import Path

# External dependencies for specialized file types
try:
    import pandas as pd
    import pyshark
    import PyPDF2
except ImportError as e:
    logging.warning(f"Missing optional dependencies: {e}")

# Windows-specific event log support
WINDOWS_SUPPORT = False
if platform.system() == "Windows":
    try:
        import win32evtlog
        WINDOWS_SUPPORT = True
    except ImportError:
        logging.warning("pywin32 not found. EVTX support is limited.")

class FormatHandlers:
    """
    R.A.V.E.N. Format Handlers
    Provides static methods to parse and extract raw text from non-standard file formats
    including Windows Event Logs (EVTX), Network Captures (PCAP), and PDF documents.
    """

    @staticmethod
    def process_evtx() -> str:
        """
        Reads local Windows Security Event Logs.
        Note: Requires administrative privileges and Windows OS.
        """
        if not WINDOWS_SUPPORT:
            return "Platform Error: Windows Event Log processing is only supported on Windows."
        
        try:
            content: List[str] = []
            # Open local security log
            hand = win32evtlog.OpenEventLog('localhost', 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for event in events:
                    # Capture basic event data string representation
                    content.append(str(event.StringInserts))
            
            return "\n".join(content)
        except Exception as e:
            logging.error(f"EVTX processing error: {e}")
            return ""

    @staticmethod
    def process_pcap(file_path: Union[str, Path]) -> str:
        """
        Parses PCAP/PCAPNG files using TShark/PyShark.
        Extracts Source/Destination IPs and DNS Queries for analysis.
        """
        content: List[str] = []
        try:
            # Note: TShark must be installed on the system for PyShark to work
            cap = pyshark.FileCapture(str(file_path))
            for packet in cap:
                try:
                    if hasattr(packet, 'ip'):
                        content.append(f"Network Flow: {packet.ip.src} -> {packet.ip.dst}")
                    if hasattr(packet, 'dns'):
                        content.append(f"DNS Query: {packet.dns.qry_name}")
                except AttributeError:
                    continue
            
            cap.close() # Ensure capture file is released
            return "\n".join(content)
        except Exception as e:
            logging.error(f"PCAP processing error: {e}")
            return ""

    @staticmethod
    def process_pdf(file_path: Union[str, Path]) -> str:
        """
        Extracts raw text from PDF documents for forensic analysis.
        """
        content: List[str] = []
        try:
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    text = page.extract_text()
                    if text:
                        content.append(text)
            return "\n".join(content)
        except Exception as e:
            logging.error(f"PDF processing error: {e}")
            return ""