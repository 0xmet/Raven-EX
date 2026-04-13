<table align="center" border="0">
  <tr>
    <td>
      <pre>
          .¬%S$$Si•
     .:iI$S$Sª°¨
.——  .:i$S$ª`  .
.:d$S$$Si' -:i$ª`  .
.:d$S'`° S:.:?`   .
.:iIS$k¬d7 j'     .
:i:-:i?$Si:-:¬,,.._
i?:--::'°::.`°:;iI$Si%¬,..
i:--:: -:-  -, -    ¨¨~^^¨¨
:--:: -  - . .° -:-:-
:--:i-  . .°  , d`?
:iSi: - , , 'j ,° .
?::?i j' ?.'j' -:.
,op:- `?  • \ °  `.
S7ji:  ` .  \ - -  .
7j?ji:   -:- -  ::--
      </pre>
    </td>
    <td align="left" valign="middle">
      <h1>R.A.V.E.N.</h1>
      <h3>Response Analysis & Verification Engine for Networks</h3>
      <p><b>Version:</b> 1.0.0<br>
      <b>Developer:</b> 0xmet</p>
      <i>"Hunt the unseen, verify the unknown."</i>
    </td>
  </tr>
</table>

---

<h1>Executive Summary</h1

**R.A.V.E.N.** is a high-performance forensic utility engineered to optimize the triage phase of digital investigations. In an era where analysts are overwhelmed by high-velocity log data, R.A.V.E.N. provides a streamlined, automated workflow to isolate, validate, and document threat indicators with surgical precision.

---
# Architecture
```text
Raven-EX/
│
├── raven.py                # Main Entry Point (Execution Core)
├── requirements.txt        # Project Dependencies
│
├── core/                   # Internal Processing Engine
│   ├── base.py             # Base classes and core definitions
│   ├── handlers.py         # Data input/output and stream handling
│   ├── filters.py          # Noise suppression & artifact cleaning logic
│   ├── patterns.py         # Advanced Regex Dictionary & Decoding engine
│   ├── reporter.py         # PDF generation & reporting module
│   ├── threat_intel.py     # Intelligence orchestration layer
│   └── vt_cache.json       # [Auto-Generated] Local cache created after first scan
│
└── reports/                # Output directory for generated forensic reports
```
---
## Core Capabilities & Technical Specifications

**R.A.V.E.N.** is engineered to bypass common log noise and focus directly on high-fidelity indicators. Below are the core technical pillars of the engine:
---

### 1. Multi-Layered Artifact Extraction
Powered by an optimized regex engine, R.A.V.E.N. parses unstructured data to isolate critical Indicators of Compromise (IoCs):
* **Network Identifiers:** Full-spectrum IPv4 tracking, Domain names, and deep URI structure parsing.
* **Cryptographic Integrity:** Simultaneous extraction of MD5, SHA1, SHA256, and SHA512 signatures.
* **System Context:** Windows (`C:\...`) and Unix (`/...`) file paths, Windows Registry (HKEY) keys, and service names.
* **Behavioral Links:** Detection of email addresses and suspicious command-line arguments.

### 2. Heuristic Base64 Decoding Engine
Attackers frequently use obfuscation to hide malicious intent. R.A.V.E.N. features an intelligent decoding layer:
* **Automated Detection:** Identifies Base64 encoded blocks within raw logs.
* **Smart Filtering:** The engine only decodes and reveals payloads containing security-critical keywords (e.g., `powershell`, `invoke`, `iex`, `download`, `bypass`), eliminating irrelevant data.
* **Encoding Compatibility:** Native support for PowerShell’s default `UTF-16LE` (Little Endian) encoding.

### 3. Advanced Threat Intelligence & Validation
Extracted data is enriched with real-time reputation scoring to provide immediate context:
* **VirusTotal API Integration:** Every identified artifact is cross-referenced against global databases for reputation scores and detection ratios.
* **MIME-Type Forensic Analysis:** Identifies internal file signatures (e.g., `/x-dosexec`, `/x-msdownload`, `/octet-stream`) to detect masquerading threats where malicious binaries are hidden as benign files.

### 4. Dynamic Noise Suppression (False Positive Mitigation)
To prevent analytical fatigue, R.A.V.E.N. applies aggressive filtering to neutralize noise:
* **White-Domain Scrubbing:** Automatically filters traffic from trusted providers like Google, Microsoft, Akamai, and Digicert.
* **TLD Validation:** Cross-references domains against a dynamic Top-Level Domain (TLD) list to eliminate syntactical false positives.
* **Process Clean-up:** Intelligently distinguishes between actual executable processes and misidentified URL strings.

### 5. Enterprise-Grade Forensic Reporting
Finalize your investigation with automated documentation:
* **Dual-Language Interface:** Full support for both English and Turkish nomenclatures.
* **PDF Export:** Generates timestamped, structured PDF reports containing all artifact metrics, reputation scores, and forensic findings for official documentation.

---


## Operational Deployment & Environment Setup

To ensure **R.A.V.E.N.** operates with maximum efficiency and thread-safety, the following high-stability deployment environment is required.

### 1) Python Runtime Specification
Designed for **Python 3.12+** with Experimental Support for Next-Gen Python Environments.

Verify your environment and ensure you are not running experimental/pre-release versions (e.g., 3.14+):
```bash
python --version
# Recommended: Python 3.12.X
```
### 2) Install All Dependencies
Open your terminal (PowerShell or CMD) in the project folder and run the following command:

```bash
pip install -r requirements.txt
```
<br>

---
### Linux Deployment
Raven-EX is fully optimized for Linux environments. The installation process automatically handles cross-platform dependencies.

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/0xmet/Raven-EX.git](https://github.com/0xmet/Raven-EX.git)
   cd Raven-EX
  

2. **Setup Virtual Environment:**
 
   ```bash
   python3 -m venv venv
   source venv/bin/activate
  

3. **Install Dependencies:**
   ```bash
     pip install -r requirements.txt 
     ```
---
## How to Use R.A.V.E.N.

R.A.V.E.N. is designed to be a "Zero-Config" forensic engine. You don't need to manage databases; just provide the logs, and the engine will do the rest.

### 1) Preparation
Place your log files or network captures (PCAP) in the project directory or have their paths ready. 

### 2) Execution
Run the main script via terminal:
```bash
python raven.py
```
### 4) Analysis Workflow (Example)
After running `python raven.py`, follow the interactive prompts to start your investigation:

1.  **Language Selection:** Choose your preferred interface language (Default: English).
    ```text
    Select Language / Dil Seçin [en/tr] (tr): en
    ```
2.  **Input Path:** Enter the full path of the file you wish to analyze.
    ```text
    Enter the file path for analysis: "C:\Users\Desktop\sample_logs.log"
    ```
3.  **Intelligence Check (Optional):** Decide if you want to perform a live reputation check via VirusTotal.
    ```text
    Perform VirusTotal lookup? [y/n] (y): y
    ```
 
    * If 'y': The engine will verify your API key. If the core/api_key.txt file is missing, it will securely ask for it:

    ```text
    [!] VirusTotal API Key Not Found.
    Please enter your API Key: <YOUR_API_KEY_HERE>
    ```
    * If 'n': The engine skips external API calls and proceeds with Local-Only Forensic Scan. This mode is faster and identifies artifacts without external data exposure.
    ---
    ### Forensic Analysis View
Once the extraction and intelligence verification steps are complete, **R.A.V.E.N.** presents a consolidated result table. This ensures you see the full picture of the investigation at a single glance:

```text
┌────┬──────────────────────┬──────────────┬─────────┐
│ #  │ Artifact / Finding   │ Reputation   │ Score   │
├────┼──────────────────────┼──────────────┼─────────┤
│ 1  │ 109.248.148.xx       │ MALICIOUS    │ 4/94    │
│ 2  │ 109.248.148.xx       │ MALICIOUS    │ 8/94    │
│ 3  │ 13.107.4.xx          │ CLEAN        │ 0/94    │
│ 4  │ 145.249.105.xx       │ MALICIOUS    │ 5/94    │
│ 5  │ 172.217.16.xx        │ CLEAN        │ 0/94    │
│ 6  │ 172.217.16.xx        │ CLEAN        │ 0/94    │
│ 7  │ 173.194.75.xx        │ CLEAN        │ 0/94    │
│ 8  │ 185.203.118.xx       │ MALICIOUS    │ 12/94   │
│ 9  │ 188.241.58.xx        │ MALICIOUS    │ 12/94   │
│ 10 │ 190.97.167.xx        │ MALICIOUS    │ 6/94    │
└────┴──────────────────────┴──────────────┴─────────┘

┌────┬──────────────────────────────┬──────────────┬─────────┐
│ #  │ Artifact / Finding           │ Reputation   │ Score   │
├────┼──────────────────────────────┼──────────────┼─────────┤
│ 1  │ http://evil-download.xyz/xx  │ MALICIOUS    │ 14/94   │
│ 2  │ https://secure-login.net/xx  │ SUSPICIOUS   │ 3/94    │
│ 3  │ http://update-service.tk/xx  │ MALICIOUS    │ 22/94   │
│ 4  │ https://google.com/search    │ CLEAN        │ 0/94    │
└────┴──────────────────────────────┴──────────────┴─────────┘

┌────┬──────────────────────────────────────────────────┬──────────────┬─────────┐
│ #  │ Artifact / Finding (SHA256)                      │ Reputation   │ Score   │
├────┼──────────────────────────────────────────────────┼──────────────┼─────────┤
│ 1  │ e3b0c44298fc1c149afbf4c8996fb92427ae...xxxxxx    │ CLEAN        │ 0/94    │
│ 2  │ 5f34d30b4281dee3195222221062921b0313...xxxxxx    │ MALICIOUS    │ 56/94   │
│ 3  │ 248d6a61d20638b8e5c026930c3e6044093c...xxxxxx    │ SUSPICIOUS   │ 7/94    │
└────┴──────────────────────────────────────────────────┴──────────────┴─────────┘

╭───┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ # │ Artifact / Finding                                                                                                │
├───┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 1 │ /octet-stream   -       0.000800        -       F       15000   15000   0       0       F       -                │
│   │ 333d2b9e99b36fb42f9e79a2833fxxxx        5d8430253a3ff3dbb52ad7009d21ac62e59exxxx        -       -                │
│ 2 │ /octet-stream   -       0.045000        -       F       2048    2048    0       0       F       -                │
│   │ ebdc6098c733b23e99daa60e55cfxxxx        5d8430253a3ff3dbb52ad7009d21ac62e59exxxx        -       -                │
│ 3 │ /x-dosexec      -       0.000100        -       F       9000    9000    0       0       F       -                │
│   │ f1aeaf72995b12d5edd3971ccbc3xxxx        13d7d00b7a50b1fcf055232dadba9c4f6ec0xxxx        -       -                │
│ 4 │ /x-dosexec      -       0.010000        -       F       8192    8192    0       0       F       -                │
│   │ 70213367847c201f65fed99dbe75xxxx        13d7d00b7a50b1fcf055232dadba9c4f6ec0xxxx        -       -                │
│ 5 │ /x-dosexec      -       0.010200        -       F       148000  148000  0       0       F       -                │
│   │ 549726b8bfb1919a343ac764d48fxxxx        13d7d00b7a50b1fcf055232dadba9c4f6ec0xxxx        -       -                │
│ 6 │ /x-msdownload   -       0.000500        -       F       4096    4096    0       0       F       -                │
│   │ ea5722ed66bd75871e24f7f88c51xxxx        0af8ab29b8de7d2a2f5aa3fd93e1b4e1ce20xxxx        -       -                │
│ 7 │ /x-msdownload   -       0.000673        -       F       11017   11017   0       0       F       -                │
│   │ a13c864980159cd9bdc94074b238xxxx        a94a8fe5ccb19ba61c4c0873d391e987982fxxxx        -       -                │
│ 8 │ /x-msdownload   -       0.001200        -       F       5120    5120    0       0       F       -                │
│   │ f05a7cc3656c9467d38d54e037c2xxxx        0af8ab29b8de7d2a2f5aa3fd93e1b4e1ce20xxxx        -       -                │
╰───┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```
---
# Disclaimer (Legal Notice)
##### *This tool is developed for educational and ethical security analysis purposes only. The developer (0xmet) is not responsible for any misuse, damage, or illegal activities performed with this software. Users are responsible for complying with local and international laws. Always obtain explicit permission before analyzing data that does not belong to you.*
