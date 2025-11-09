import os, sys, json, csv, hashlib, argparse, time
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter

try:
    import requests
    VT_AVAILABLE = True
except:
    VT_AVAILABLE = False
    print("requests not found. VirusTotal integration disabled.")

try:
    import yara
    YARA_AVAILABLE = True
except:
    YARA_AVAILABLE = False
    print("yara-python not found. YARA scanning disabled.")

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as views
    EVTX = True
except:
    EVTX = False
    print("python-evtx not found. Offline .evtx parsing disabled.")

try:
    import win32evtlog
    import win32evtlogutil
    LIVE = True
except:
    LIVE = False
    print("pywin32 not found. Live log query disabled.")

# === CONFIG ===
DEFAULT_LOGS = ["System", "Security", "Application"]
HASH_TYPE = "sha256"  # Changed to SHA256 for VT
BLOCK_SIZE = 65536
VT_API_KEY = None  # Set via --vt-key or environment variable
VT_RATE_LIMIT = 4  # Free tier: 4 requests/min

# SOC Detection Rules
THREAT_RULES = {
    "brute_force": {"event_id": 4625, "threshold": 5, "window_min": 5},
    "privilege_escalation": {"event_id": 4672, "suspicious_accounts": ["Guest", "DefaultAccount"]},
    "account_lockout": {"event_id": 4740, "threshold": 3},
    "powershell_exec": {"event_id": 4104, "keywords": ["downloadstring", "invoke-expression", "base64"]},
    "new_service": {"event_id": 7045, "suspicious_paths": ["temp", "appdata", "programdata"]}
}

# Basic YARA rules for common malware patterns
BUILTIN_YARA_RULES = """
rule Suspicious_Encoded_PowerShell {
    meta:
        description = "Detects base64 encoded PowerShell commands"
        severity = "medium"
    strings:
        $powershell = "powershell" nocase
        $encoded = "encodedcommand" nocase
        $base64 = /[A-Za-z0-9+\/]{50,}={0,2}/
    condition:
        $powershell and ($encoded or $base64)
}

rule Suspicious_Download_Execute {
    meta:
        description = "Detects download and execute patterns"
        severity = "high"
    strings:
        $download1 = "DownloadFile" nocase
        $download2 = "DownloadString" nocase
        $download3 = "WebClient" nocase
        $exec1 = "Invoke-Expression" nocase
        $exec2 = "iex" nocase
        $exec3 = "Start-Process" nocase
    condition:
        any of ($download*) and any of ($exec*)
}

rule Potential_Ransomware_Note {
    meta:
        description = "Detects potential ransomware ransom notes"
        severity = "critical"
    strings:
        $ransom1 = "bitcoin" nocase
        $ransom2 = "decrypt" nocase
        $ransom3 = "ransom" nocase
        $ransom4 = "encrypted" nocase
        $contact = /@/ 
    condition:
        3 of them
}

rule Mimikatz_Keywords {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        severity = "critical"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa" nocase
        $m3 = "lsadump" nocase
        $m4 = "kerberos::golden" nocase
    condition:
        any of them
}
"""

# === HELPERS ===
def hash_file(path, algo="sha256"):
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(BLOCK_SIZE), b""):
                h.update(block)
        return h.hexdigest()
    except: return "ERROR"

def save_csv(data, path):
    if not data: return
    keys = data[0].keys()
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)

def print_summary(events, event_type="events"):
    """Print analysis summary for SOC reporting"""
    if not events:
        print(f"\n[SUMMARY] No {event_type} found")
        return
    
    print(f"\n{'='*60}")
    print(f"[SUMMARY] {event_type.upper()} ANALYSIS")
    print(f"{'='*60}")
    print(f"Total Events: {len(events)}")
    
    if "ID" in events[0]:
        id_counts = Counter(e["ID"] for e in events)
        print(f"\nTop Event IDs:")
        for eid, count in id_counts.most_common(5):
            print(f"  • Event {eid}: {count} occurrences")
    
    if "Time" in events[0]:
        times = [datetime.strptime(e["Time"], "%Y-%m-%d %H:%M:%S") for e in events]
        print(f"\nTime Range:")
        print(f"  First: {min(times)}")
        print(f"  Last:  {max(times)}")
    
    print(f"{'='*60}\n")

def detect_brute_force(events, threshold=5, window_min=5):
    """Detect potential brute force attacks (multiple failed logins)"""
    if not events:
        return []
    
    alerts = []
    by_user = {}
    
    for e in events:
        if e.get("ID") != 4625:
            continue
        
        msg = e.get("Message", "")
        user = "Unknown"
        if "Account Name:" in msg:
            user = msg.split("Account Name:")[1].split()[0].strip()
        
        if user not in by_user:
            by_user[user] = []
        by_user[user].append(datetime.strptime(e["Time"], "%Y-%m-%d %H:%M:%S"))
    
    for user, times in by_user.items():
        if len(times) >= threshold:
            times.sort()
            window = timedelta(minutes=window_min)
            for i in range(len(times) - threshold + 1):
                if times[i + threshold - 1] - times[i] <= window:
                    alerts.append({
                        "Alert": "BRUTE_FORCE",
                        "Severity": "HIGH",
                        "User": user,
                        "Attempts": len(times),
                        "FirstSeen": times[0].strftime("%Y-%m-%d %H:%M:%S"),
                        "LastSeen": times[-1].strftime("%Y-%m-%d %H:%M:%S")
                    })
                    break
    
    return alerts

# === VIRUSTOTAL INTEGRATION ===
def check_virustotal(file_hash, api_key):
    """Check file hash against VirusTotal database"""
    if not VT_AVAILABLE or not api_key:
        return None
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0)
            }
        elif response.status_code == 404:
            return {"status": "not_found"}
        else:
            return {"status": f"error_{response.status_code}"}
    except Exception as e:
        return {"status": f"error: {str(e)}"}

def batch_vt_check(files, api_key, rate_limit=4):
    """Check multiple files against VirusTotal with rate limiting"""
    if not api_key:
        print("\n[!] No VirusTotal API key provided. Use --vt-key or set VT_API_KEY env variable")
        return files
    
    print(f"\n[VT] Checking {len(files)} files against VirusTotal...")
    print(f"[VT] Rate limit: {rate_limit} requests/min (this may take a while)")
    
    for i, f in enumerate(files):
        if not f.get("Hash") or f["Hash"] == "ERROR":
            f["VT_Detections"] = "N/A"
            f["VT_Status"] = "no_hash"
            continue
        
        # Rate limiting
        if i > 0 and i % rate_limit == 0:
            print(f"[VT] Rate limit pause... ({i}/{len(files)})")
            time.sleep(60)
        
        result = check_virustotal(f["Hash"], api_key)
        
        if result:
            if result.get("status") == "not_found":
                f["VT_Detections"] = "0"
                f["VT_Status"] = "clean/unknown"
            elif "error" in str(result.get("status", "")):
                f["VT_Detections"] = "ERROR"
                f["VT_Status"] = result["status"]
            else:
                detections = result.get("malicious", 0) + result.get("suspicious", 0)
                f["VT_Detections"] = str(detections)
                f["VT_Status"] = "MALWARE" if detections > 0 else "clean"
                
                if detections > 0:
                    print(f"[!] ALERT: {f['Name']} - {detections} detections!")
        
        if (i + 1) % 10 == 0:
            print(f"[VT] Processed {i + 1}/{len(files)} files...")
    
    print(f"[VT] Completed!")
    return files

# === YARA SCANNING ===
def compile_yara_rules(rules_path=None):
    """Compile YARA rules from file or use built-in rules"""
    if not YARA_AVAILABLE:
        return None
    
    try:
        if rules_path and os.path.exists(rules_path):
            print(f"[YARA] Loading rules from {rules_path}")
            return yara.compile(filepath=rules_path)
        else:
            print("[YARA] Using built-in detection rules")
            return yara.compile(source=BUILTIN_YARA_RULES)
    except Exception as e:
        print(f"[!] YARA compilation error: {e}")
        return None

def yara_scan_file(file_path, rules):
    """Scan a single file with YARA rules"""
    try:
        matches = rules.match(file_path)
        if matches:
            return [{"rule": m.rule, "meta": m.meta} for m in matches]
        return []
    except:
        return []

def yara_scan_files(files, rules):
    """Scan multiple files with YARA rules"""
    if not rules:
        return files
    
    print(f"\n[YARA] Scanning {len(files)} files...")
    detected = 0
    
    for f in files:
        matches = yara_scan_file(f["Path"], rules)
        if matches:
            detected += 1
            match_str = ", ".join([m["rule"] for m in matches])
            severity = matches[0]["meta"].get("severity", "unknown")
            f["YARA_Match"] = match_str
            f["YARA_Severity"] = severity
            print(f"[!] YARA HIT: {f['Name']} -> {match_str} (Severity: {severity})")
        else:
            f["YARA_Match"] = "clean"
            f["YARA_Severity"] = "none"
    
    print(f"[YARA] Scan complete: {detected} suspicious files detected")
    return files

# === 1. LIVE LOG PARSER ===
def parse_live(logname="Security", ids=None, hours=24, max_n=100):
    if not LIVE: return []
    print(f"[LIVE] Reading {logname} (last {hours}h)...")
    server = "localhost"
    hand = win32evtlog.OpenEventLog(server, logname)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    cutoff = datetime.now().timestamp() - (hours * 3600)
    events = []
    count = 0

    try:
        while count < max_n:
            recs = win32evtlog.ReadEventLog(hand, flags, 0)
            if not recs: break
            for r in recs:
                if r.TimeGenerated.timestamp() < cutoff: break
                if ids and r.EventID not in ids: continue
                try:
                    msg = win32evtlogutil.SafeFormatMessage(r, logname)
                except:
                    msg = ""
                events.append({
                    "Time": r.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                    "ID": r.EventID,
                    "Type": {1:"ERROR",2:"WARN",4:"INFO"}.get(r.EventType, r.EventType),
                    "Source": r.SourceName,
                    "Message": msg.replace("\n"," ").replace("\r","")[:500]
                })
                count += 1
        print(f"   {len(events)} events")
    finally:
        win32evtlog.CloseEventLog(hand)
    
    return events

# === 2. EVTX FILE PARSER ===
def parse_evtx(file_path, ids=None, max_n=500):
    if not EVTX: return []
    print(f"[EVTX] Parsing {Path(file_path).name}...")
    records = []
    with evtx.Evtx(file_path) as log:
        for i, record in enumerate(log.records()):
            if max_n and i >= max_n: break
            try:
                xml = record.xml()
                root = views.etree.fromstring(xml)
                sys = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}System")
                eid = int(sys.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID").text)
                if ids and eid not in ids: continue
                time = sys.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated").attrib["SystemTime"][:19]
                msg = (root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}RenderingInfo/Message") or "").text or ""
                records.append({
                    "Time": time.replace("T", " "),
                    "ID": eid,
                    "Level": sys.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}Level").text,
                    "Provider": sys.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}Provider").attrib.get("Name", ""),
                    "Message": msg.replace("\n"," ").replace("\r","")[:500]
                })
            except: continue
    print(f"   {len(records)} events")
    return records

# === 3. FILE SCANNER ===
def scan_dir(path, exts=None, hash_it=False, min_mb=None, yara_rules=None, vt_key=None):
    print(f"[SCAN] {path}...")
    path = Path(path)
    files = []
    suspicious_count = 0
    
    for f in path.rglob("*"):
        if not f.is_file(): continue
        if exts and f.suffix.lower() not in exts: continue
        if min_mb and f.stat().st_size < min_mb * 1024**2: continue
        
        # Flag suspicious files
        suspicious = False
        if f.suffix.lower() in [".exe", ".dll", ".ps1", ".vbs", ".bat", ".js", ".jar"]:
            if any(x in str(f).lower() for x in ["temp", "appdata", "downloads", "programdata"]):
                suspicious = True
                suspicious_count += 1
        
        files.append({
            "Path": str(f),
            "Name": f.name,
            "Ext": f.suffix.lower(),
            "SizeMB": round(f.stat().st_size / 1024**2, 2),
            "Modified": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
            "Hash": hash_file(f, HASH_TYPE) if hash_it else "",
            "Suspicious": "YES" if suspicious else "NO"
        })
    
    print(f"   {len(files)} files ({suspicious_count} suspicious)")
    
    # YARA scanning
    if yara_rules and YARA_AVAILABLE:
        files = yara_scan_files(files, yara_rules)
    
    # VirusTotal checking
    if vt_key and hash_it:
        files = batch_vt_check(files, vt_key)
    
    return files

# === CLI ===
if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Enterprise SOC Log & Threat Hunter",
        epilog="Example: python log_hunter.py scan C:\\Temp --hash --yara --vt-key YOUR_KEY"
    )
    p.add_argument("mode", choices=["log", "evtx", "scan"], help="log=live, evtx=file, scan=files")
    p.add_argument("target", help="Log name, .evtx path, or folder")
    p.add_argument("-i", "--ids", help="Event IDs (comma)", type=lambda x: [int(i) for i in x.split(",")])
    p.add_argument("-o", "--out", help="Output CSV", default="out.csv")
    p.add_argument("--hash", action="store_true", help="Calculate SHA256 file hashes")
    p.add_argument("--ext", help="File extensions (.exe,.dll)")
    p.add_argument("--detect", action="store_true", help="Run threat detection rules")
    p.add_argument("--summary", action="store_true", help="Print analysis summary", default=True)
    p.add_argument("--yara", action="store_true", help="Run YARA scans (built-in rules)")
    p.add_argument("--yara-rules", help="Path to custom YARA rules file")
    p.add_argument("--vt-key", help="VirusTotal API key", default=os.getenv("VT_API_KEY"))
    p.add_argument("--vt-rate", type=int, default=4, help="VT API rate limit (req/min)")
    args = p.parse_args()

    data = []
    
    if args.mode == "log" and LIVE:
        data = parse_live(args.target, args.ids)
        
        # Threat detection for Security logs
        if args.detect and args.target.lower() == "security":
            alerts = detect_brute_force(data)
            if alerts:
                print(f"\n{'!'*60}")
                print(f"[ALERTS] {len(alerts)} THREAT(S) DETECTED")
                print(f"{'!'*60}")
                for alert in alerts:
                    print(f"\n⚠️  {alert['Alert']} - Severity: {alert['Severity']}")
                    print(f"   User: {alert['User']}")
                    print(f"   Attempts: {alert['Attempts']}")
                    print(f"   Timeframe: {alert['FirstSeen']} to {alert['LastSeen']}")
                
                alert_file = args.out.replace(".csv", "_alerts.csv")
                save_csv(alerts, alert_file)
                print(f"\n[!] Alerts saved -> {alert_file}")
        
    elif args.mode == "evtx" and EVTX and args.target.endswith(".evtx"):
        data = parse_evtx(args.target, args.ids)
        
    elif args.mode == "scan":
        exts = [f".{e.lstrip('.')}" for e in args.ext.split(",")] if args.ext else None
        
        # Compile YARA rules if requested
        yara_rules = None
        if args.yara or args.yara_rules:
            yara_rules = compile_yara_rules(args.yara_rules)
        
        data = scan_dir(args.target, exts, args.hash, None, yara_rules, args.vt_key)
        
    else:
        print("Invalid mode or missing dependencies")
        sys.exit(1)

    if data:
        save_csv(data, args.out)
        print(f"\n[✓] Saved -> {args.out}")
        
        if args.summary:
            print_summary(data, args.mode)
    else:
        print("\n[!] No data collected")
