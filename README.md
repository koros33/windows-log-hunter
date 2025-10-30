## 🧠 `log_hunter.py` — Enterprise SOC Log & Threat Hunter

`log_hunter.py` is a **lightweight Security Operations Center (SOC) toolkit** for **Windows event log analysis**, **file scanning**, **YARA detection**, and **VirusTotal integration**.
It’s designed for analysts, blue teams, and digital forensics researchers who need to **hunt threats** and **analyze logs or suspicious files** both live and offline.

---

### ⚙️ Features

✅ **Windows Event Log Analysis**

* Live Security/System/Application event log parsing
* `.evtx` offline log parsing (if `python-evtx` installed)
* Event filtering by ID
* Summary statistics and time range reporting

✅ **Threat Detection**

* Built-in rules for:

  * Brute force attacks (Event ID 4625)
  * Privilege escalation
  * Account lockouts
  * Suspicious PowerShell execution
  * New service installations

✅ **File Scanning**

* Recursive directory scanning
* Suspicious file flagging (by path and extension)
* File hashing (SHA256)
* Optional YARA scan & VirusTotal lookup

✅ **YARA Integration**

* Built-in YARA rules for:

  * Encoded PowerShell
  * Download & execute patterns
  * Ransomware notes
  * Mimikatz indicators
* Supports custom `.yar` rule files

✅ **VirusTotal Integration**

* Hash lookup against VirusTotal API (v3)
* Rate-limit control for free tier (4 req/min)
* Detection summaries saved to CSV

✅ **SOC Reporting**

* CSV export of all logs or scan results
* Summary of key events and threat findings

---

### 🧩 Requirements

**Python 3.8+**
Install required modules:

```bash
pip install requests yara-python python-evtx pywin32
```

> If you don’t need some features, you can skip the related packages.
> The script gracefully disables unavailable modules.

---

### 🧪 Usage

#### 🟩 1. Live Log Hunting

Parse Windows Security logs (last 24 hours):

```bash
python log_hunter.py log Security --detect --summary
```

Specify certain event IDs:

```bash
python log_hunter.py log Security -i 4625,4672
```

---

#### 🟨 2. Offline `.evtx` Log Analysis

Parse an exported Event Log file:

```bash
python log_hunter.py evtx C:\Logs\Security.evtx -i 4625,4672 -o evtx_results.csv
```

---

#### 🟦 3. Directory File Scanning

Recursively scan a folder for suspicious files:

```bash
python log_hunter.py scan C:\Users\Public\Downloads --hash --summary
```

With YARA and VirusTotal:

```bash
python log_hunter.py scan C:\Samples --hash --yara --vt-key YOUR_VT_API_KEY
```

Custom extensions:

```bash
python log_hunter.py scan C:\ --ext .exe,.dll,.ps1
```

---

### ⚙️ Command-Line Options

| Option                | Description                                          |
| --------------------- | ---------------------------------------------------- |
| `log`, `evtx`, `scan` | Mode selection (live log, evtx file, or folder scan) |
| `target`              | Log name, `.evtx` file, or directory path            |
| `-i`, `--ids`         | Filter by event IDs (comma-separated)                |
| `-o`, `--out`         | Output CSV filename (default: `out.csv`)             |
| `--hash`              | Calculate SHA256 hashes                              |
| `--detect`            | Run built-in SOC threat detection                    |
| `--summary`           | Print analysis summary                               |
| `--ext`               | File extensions to include (e.g. `.exe,.dll`)        |
| `--yara`              | Enable built-in YARA scanning                        |
| `--yara-rules`        | Path to custom `.yar` rule file                      |
| `--vt-key`            | VirusTotal API key (or use env var `VT_API_KEY`)     |
| `--vt-rate`           | VirusTotal rate limit (req/min, default=4)           |

---

### 🔐 Example Workflow

1. **Collect live logs**

   ```bash
   python log_hunter.py log Security --detect
   ```

2. **Export and analyze `.evtx` logs**

   ```bash
   python log_hunter.py evtx Security.evtx -o report.csv
   ```

3. **Scan suspect directory with YARA + VT**

   ```bash
   python log_hunter.py scan C:\Suspect --hash --yara --vt-key YOUR_KEY
   ```

4. **View summary**

   ```
   [SUMMARY] SCAN ANALYSIS
   Total Events: 300
   Top Event IDs:
     • Event 4625: 20 occurrences
   Time Range: 2025-10-29 → 2025-10-30
   ```

---

### 🧰 Output Files

| File             | Description                            |
| ---------------- | -------------------------------------- |
| `out.csv`        | Main results (logs or scan data)       |
| `out_alerts.csv` | Threat alerts (e.g., brute force)      |
| `yara_hits.csv`  | YARA detection results (if applicable) |

---

### 🧠 Notes

* Works best on **Windows systems** (for live event logs).
* On Linux/macOS, only EVTX parsing and file scanning modes will work.
* VirusTotal free API keys are limited — respect rate limits or use a premium key.
* Built-in YARA rules can be extended for enterprise detection frameworks.


### 📜 License

MIT License — free for research, education, and SOC toolkits.

