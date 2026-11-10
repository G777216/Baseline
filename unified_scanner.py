#!/usr/bin/env python3
"""
================================================================================
UNIFIED FILESYSTEM SCANNER AND INTEGRITY CHECKER (v2.0 Forensic Edition)
================================================================================
An agentless, forensic-grade filesystem auditing and differential analysis tool.

Core Features:
- Dual-Stream Hashing (MD5 + SHA-256 in a single 128KB I/O pass)
- Multi-Source Threat Intelligence (CIRCL Hashlookup + MalwareBazaar + VirusTotal v3)
- SUID/SGID Privilege Escalation Detection (POSIX/Linux)
- Cross-Platform Path Normalization (/home/user -> /home/USER, C:\\Users\\user -> C:\\Users\\USER)
- Critical Security Threat Categorization (modified binaries, drop zones, script drops)
- Interactive HTML Dashboard generation (zero external CDN dependencies)
- Transparent Gzip Compression (.json and .json.gz auto-detection)
- Structured CSV & JSON diffing engine
- Zero external dependencies (uses standard Python 3.7+ library only)
================================================================================
"""

import os
import sys
import json
import csv
import re
import time
import socket
import hashlib
import argparse
import shutil
import gzip
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# ----------------------------------------------------------------------
# 1. Forensic Hashing & Filesystem Scanning Engine
# ----------------------------------------------------------------------

def calculate_hashes(file_path, max_bytes=None):
    """
    Simultaneously calculates MD5 and SHA-256 hashes in a single I/O stream
    using 128 KB buffer chunks for maximum disk throughput.
    """
    try:
        hash_md5 = hashlib.md5()
        hash_sha256 = hashlib.sha256()
        bytes_read = 0

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(131072), b""):
                hash_md5.update(chunk)
                hash_sha256.update(chunk)
                bytes_read += len(chunk)
                if max_bytes and bytes_read >= max_bytes:
                    break

        return hash_md5.hexdigest(), hash_sha256.hexdigest()
    except (PermissionError, OSError, IOError):
        return None, None

def process_file_task(args):
    """Worker task executed by parallel worker processes."""
    file_path, max_bytes = args
    try:
        stats = os.stat(file_path)
        file_size = stats.st_size
        
        # Skip empty files
        if file_size == 0:
            return None

        # Capture POSIX permissions & SUID/SGID bits on Linux/Unix
        mode = stats.st_mode
        permissions = oct(mode)[-4:] if hasattr(os, "chmod") else "N/A"
        is_suid = bool(mode & 0o4000) if os.name != "nt" else False
        is_sgid = bool(mode & 0o2000) if os.name != "nt" else False
            
        md5_hash, sha256_hash = calculate_hashes(file_path, max_bytes=max_bytes)
        if md5_hash:
            return {
                "filename": os.path.basename(file_path),
                "full_path": file_path,
                "modification_datetime": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "md5_hash": md5_hash,
                "sha256_hash": sha256_hash,
                "size_bytes": file_size,
                "permissions": permissions,
                "is_suid": is_suid,
                "is_sgid": is_sgid
            }
    except (PermissionError, OSError, FileNotFoundError):
        pass
    return None

def format_time(seconds):
    """Format seconds into HH:MM:SS."""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"

def format_size(size_bytes):
    """Convert bytes to human-readable format."""
    if size_bytes == 'N/A' or size_bytes is None:
        return 'N/A'
    try:
        size = float(size_bytes)
    except (ValueError, TypeError):
        return str(size_bytes)
        
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def is_gzipped(file_path):
    """Check if file starts with gzip magic number (0x1f, 0x8b)."""
    try:
        with open(file_path, 'rb') as f:
            return f.read(2) == b'\x1f\x8b'
    except Exception:
        return False

def save_json(output_file, data, compress=False):
    """Save data as JSON or compressed gzip JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    if compress or output_file.endswith(".gz"):
        if not output_file.endswith(".gz"):
            output_file += ".gz"
        with gzip.open(output_file, 'wt', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    else:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    return output_file

def load_json_scan(file_path):
    """Loads and validates JSON scan, automatically detecting gzipped files."""
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' does not exist.")
        return None
    try:
        if is_gzipped(file_path) or file_path.endswith('.gz'):
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                return json.load(f)
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"[-] Error parsing scan JSON in '{file_path}': {e}")
        return None

def scan_filesystem(start_path=None, output_file=None, verbose=True, compress=False, max_file_mb=None):
    """
    Recursively scans the filesystem using parallel multiprocessing to calculate
    dual MD5 and SHA-256 hashes with optional size limits and gzip compression.
    """
    if start_path is None:
        start_path = "C:\\" if os.name == "nt" else "/"

    hostname = socket.gethostname()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_file is None:
        ext = ".json.gz" if compress else ".json"
        output_file = os.path.join(os.getcwd(), f"filesystem_scan_{timestamp}{ext}")

    # Directories to skip to avoid hanging, locks, or pseudo-filesystems
    if os.name == "nt":
        skip_dirs = {
            "Windows", "Program Files", "Program Files (x86)",
            "System Volume Information", "$Recycle.Bin", "AppData"
        }
    else:
        skip_dirs = {"proc", "sys", "dev", "run", "tmp", "var/lib/docker"}

    max_workers = max(1, multiprocessing.cpu_count() - 1)
    results = []
    start_time = time.time()
    save_interval = 1000
    max_bytes = int(max_file_mb * 1024 * 1024) if max_file_mb else None

    print("\n" + "-"*75)
    print(f"[*] Starting Dual-Hash Filesystem Scan (MD5 + SHA-256)")
    print(f"[*] Root Path:    {start_path}")
    print(f"[*] Hostname:     {hostname}")
    print(f"[*] Workers:      {max_workers} CPU cores")
    print(f"[*] Compression:  {'Enabled (Gzip)' if compress or output_file.endswith('.gz') else 'Disabled'}")
    if max_file_mb:
        print(f"[*] Max Hash Cap: {max_file_mb} MB per file")
    print(f"[*] Output file:  {output_file}")
    print("-"*75 + "\n")

    tasks = []
    try:
        print("[*] Enumerating files...", end='\r')
        for root, dirs, files in os.walk(start_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in files:
                tasks.append(os.path.join(root, filename))

        total_tasks = len(tasks)
        print(f"[*] Found {total_tasks:,} files to analyze. Starting parallel dual-hashing...".ljust(85))

        chunk_size = 2000
        processed_total = 0

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            for chunk_start in range(0, total_tasks, chunk_size):
                chunk_end = min(chunk_start + chunk_size, total_tasks)
                chunk_tasks = tasks[chunk_start:chunk_end]

                future_to_file = {executor.submit(process_file_task, (f, max_bytes)): f for f in chunk_tasks}

                for future in as_completed(future_to_file):
                    res = future.result()
                    if res:
                        results.append(res)

                    processed_total += 1

                    if processed_total % 50 == 0 or processed_total == total_tasks:
                        elapsed = time.time() - start_time
                        percent = (processed_total / total_tasks) * 100
                        current_file = future_to_file.get(future, "Scanning...")
                        display_file = "..." + current_file[-50:] if len(current_file) > 53 else current_file

                        status_msg = f"Progress: {percent:6.2f}% | Files: {processed_total:,}/{total_tasks:,} | {display_file:<53} | {format_time(elapsed)}"

                        verbose_step = 100 if verbose else 1000
                        if verbose and processed_total % verbose_step == 0:
                            print(f"[*] {status_msg}".ljust(120))
                        else:
                            print(status_msg.ljust(120), end='\r')

                        if len(results) > 0 and len(results) % save_interval == 0:
                            save_json(output_file, results, compress=compress)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user! Finalizing partial snapshot...")

    total_time = time.time() - start_time
    save_json(output_file, results, compress=compress)

    file_size_on_disk = os.path.getsize(output_file) if os.path.exists(output_file) else 0

    print(f"\n[+] Scan finished!")
    print(f"    - Total files indexed: {len(results):,}")
    print(f"    - Total time elapsed:  {format_time(total_time)}")
    print(f"    - Snapshot file:       {output_file} ({format_size(file_size_on_disk)})\n")
    return output_file

# ----------------------------------------------------------------------
# 2. Path Normalization & Diffing Engine
# ----------------------------------------------------------------------

def normalize_path(path):
    """
    Normalizes user-specific paths to generic placeholders.
    Allows accurate comparison between systems with different usernames.
    """
    # Linux: Replace /home/<username>/ and /root/ with /home/USER/
    normalized = re.sub(r'/home/[^/]+/', '/home/USER/', path)
    normalized = normalized.replace('/root/', '/home/USER/')

    # Windows: Replace C:\Users\<username>\ with C:\Users\USER\
    normalized = re.sub(r'(?i)C:\\Users\\[^\\]+\\', r'C:\\Users\\USER\\', normalized)
    return normalized

def create_file_index(scan_data):
    """Index scan records by normalized path."""
    index = {}
    for entry in scan_data:
        original = entry.get('full_path')
        if original:
            norm = normalize_path(original)
            entry_copy = entry.copy()
            entry_copy['normalized_path'] = norm
            index[norm] = entry_copy
    return index

def compare_scans(clean_scan_file, target_scan_file, output_file=None):
    """
    Compares baseline and target scans.
    Identifies modified, new, deleted files, and permission anomalies (SUID).
    """
    clean_data = load_json_scan(clean_scan_file)
    if clean_data is None:
        return None

    target_data = load_json_scan(target_scan_file)
    if target_data is None:
        return None

    clean_dict = create_file_index(clean_data)
    target_dict = create_file_index(target_data)

    modified_files = []
    new_files = []
    deleted_files = []

    # Check for modified & new files
    for norm_path, target_info in target_dict.items():
        if norm_path in clean_dict:
            clean_info = clean_dict[norm_path]
            
            # Prefer SHA-256 comparison if available in both, otherwise fall back to MD5
            hash_mismatch = False
            if 'sha256_hash' in target_info and 'sha256_hash' in clean_info:
                hash_mismatch = (target_info['sha256_hash'] != clean_info['sha256_hash'])
            elif 'md5_hash' in target_info and 'md5_hash' in clean_info:
                hash_mismatch = (target_info['md5_hash'] != clean_info['md5_hash'])

            # SUID Privilege Escalation Flag: File gained SUID bit on Linux
            suid_escalation = (not clean_info.get('is_suid', False) and target_info.get('is_suid', False))

            if hash_mismatch or suid_escalation:
                modified_files.append({
                    'normalized_path': norm_path,
                    'clean_system_path': clean_info.get('full_path'),
                    'target_system_path': target_info.get('full_path'),
                    'filename': target_info.get('filename'),
                    'clean_md5': clean_info.get('md5_hash'),
                    'target_md5': target_info.get('md5_hash'),
                    'clean_sha256': clean_info.get('sha256_hash', 'N/A'),
                    'target_sha256': target_info.get('sha256_hash', 'N/A'),
                    'clean_modification_time': clean_info.get('modification_datetime'),
                    'target_modification_time': target_info.get('modification_datetime'),
                    'clean_size': clean_info.get('size_bytes', 'N/A'),
                    'target_size': target_info.get('size_bytes', 'N/A'),
                    'clean_permissions': clean_info.get('permissions', 'N/A'),
                    'target_permissions': target_info.get('permissions', 'N/A'),
                    'suid_escalation': suid_escalation,
                    'threat_verdict': 'UNCHECKED',
                    'threat_details': 'Pending analysis',
                    'threat_source': 'None'
                })
        else:
            new_files.append({
                'normalized_path': norm_path,
                'target_system_path': target_info.get('full_path'),
                'filename': target_info.get('filename'),
                'md5_hash': target_info.get('md5_hash'),
                'sha256_hash': target_info.get('sha256_hash', 'N/A'),
                'modification_datetime': target_info.get('modification_datetime'),
                'size_bytes': target_info.get('size_bytes', 'N/A'),
                'permissions': target_info.get('permissions', 'N/A'),
                'is_suid': target_info.get('is_suid', False),
                'threat_verdict': 'UNCHECKED',
                'threat_details': 'Pending analysis',
                'threat_source': 'None'
            })

    # Check for deleted files
    for norm_path, clean_info in clean_dict.items():
        if norm_path not in target_dict:
            deleted_files.append({
                'normalized_path': norm_path,
                'clean_system_path': clean_info.get('full_path'),
                'filename': clean_info.get('filename'),
                'md5_hash': clean_info.get('md5_hash'),
                'sha256_hash': clean_info.get('sha256_hash', 'N/A'),
                'modification_datetime': clean_info.get('modification_datetime'),
                'size_bytes': clean_info.get('size_bytes', 'N/A'),
                'permissions': clean_info.get('permissions', 'N/A'),
                'threat_verdict': 'N/A',
                'threat_details': 'Deleted from target',
                'threat_source': 'None'
            })

    results = {
        'analysis_timestamp': datetime.now().isoformat(),
        'clean_scan_file': clean_scan_file,
        'target_scan_file': target_scan_file,
        'clean_total_files': len(clean_dict),
        'target_total_files': len(target_dict),
        'summary': {
            'modified_files_count': len(modified_files),
            'new_files_count': len(new_files),
            'deleted_files_count': len(deleted_files)
        },
        'modified_files': modified_files,
        'new_files': new_files,
        'deleted_files': deleted_files
    }

    if output_file:
        save_json(output_file, results)

    return results

# ----------------------------------------------------------------------
# 3. Threat Classification & Analytics
# ----------------------------------------------------------------------

def is_system_binary(path):
    """Identify if path points to a sensitive operating system binary directory."""
    linux_paths = ['/bin/', '/usr/bin/', '/sbin/', '/usr/sbin/', '/lib/', '/usr/lib/', '/lib64/', '/usr/lib64/']
    if any(path.startswith(bp) for bp in linux_paths):
        return True

    path_lower = path.lower()
    windows_paths = [
        'c:\\windows\\system32',
        'c:\\windows\\syswow64',
        'c:\\windows\\explorer.exe',
        'c:\\windows\\regedit.exe'
    ]
    return any(wp in path_lower for wp in windows_paths)

def is_suspicious_file(file_info):
    """Detect suspicious executable extensions, hidden scripts, drop zones, or SUID."""
    path = file_info.get('normalized_path', '')
    path_lower = path.lower()
    filename = file_info.get('filename', '')
    filename_lower = filename.lower()

    if file_info.get('is_suid', False) or file_info.get('suid_escalation', False):
        return True

    suspicious_exts = [
        '.sh', '.exe', '.pl', '.py', '.rb', '.php', '.elf',
        '.bat', '.ps1', '.vbs', '.js', '.scr', '.dll', '.cmd', '.hta'
    ]
    if any(filename_lower.endswith(ext) for ext in suspicious_exts):
        return True

    # Hidden files in non-home directories (Linux)
    if filename.startswith('.') and '/home/' not in path:
        return True

    # Common attacker drop zones / temp directories
    drop_zones = [
        '/tmp/', '/var/tmp/', '/dev/shm/',
        '\\temp\\', '\\appdata\\local\\temp\\', '\\windows\\temp\\'
    ]
    if any(dz in path_lower for dz in drop_zones):
        return True

    return False

def categorize_findings(comparison_data):
    """Categorizes diffs into structured security findings with severity rankings."""
    modified = comparison_data.get('modified_files', [])
    new = comparison_data.get('new_files', [])
    deleted = comparison_data.get('deleted_files', [])

    mod_binaries = []
    suspicious_new = []
    suid_findings = []
    other_modified = []
    other_new = []

    for f in modified:
        if f.get('suid_escalation', False):
            suid_findings.append(f)
        elif is_system_binary(f['normalized_path']):
            mod_binaries.append(f)
        else:
            other_modified.append(f)

    for f in new:
        if is_suspicious_file(f):
            suspicious_new.append(f)
        else:
            other_new.append(f)

    return {
        'suid_findings': suid_findings,
        'mod_binaries': mod_binaries,
        'suspicious_new': suspicious_new,
        'other_modified': other_modified,
        'other_new': other_new,
        'deleted': deleted
    }

# ----------------------------------------------------------------------
# 4. Multi-Source Threat Intelligence (CIRCL + MalwareBazaar + VirusTotal)
# ----------------------------------------------------------------------

CACHE_FILE = "threat_intel_cache.json"

def load_threat_intel_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return {}

def save_threat_intel_cache(cache):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass

def load_threat_intel_config():
    """
    Loads VirusTotal API key and settings securely without exposing secrets to Git.
    Prioritizes:
    1. vt_config.json (local ignored file)
    2. VT_API_KEY environment variable
    """
    config = {
        "virustotal_api_key": os.environ.get("VT_API_KEY", ""),
        "enable_circl": True,
        "enable_malwarebazaar": True,
        "rate_limit_seconds": 15
    }
    candidates = [
        "vt_config.json",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "vt_config.json")
    ]
    for c in candidates:
        if os.path.exists(c):
            try:
                with open(c, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        config.update(data)
                        break
            except Exception:
                pass
    return config

_LAST_VT_CALL = 0.0

def query_threat_intel(sha256_hash, md5_hash=None, config=None, cache=None):
    """
    Enriches a file hash using free CIRCL Hashlookup, MalwareBazaar, and VirusTotal v3.
    """
    global _LAST_VT_CALL
    target_hash = sha256_hash if (sha256_hash and sha256_hash != 'N/A') else md5_hash
    if not target_hash or target_hash == 'N/A':
        return {"verdict": "UNKNOWN", "details": "No Hash Available", "source": "None"}

    if cache is None:
        cache = load_threat_intel_cache()

    # 1. Local Cache Lookup (0 API cost)
    if target_hash in cache:
        return cache[target_hash]

    if config is None:
        config = load_threat_intel_config()

    # 2. Check CIRCL Hashlookup (NSRL known legitimate OS binaries & KnownMalicious database)
    if config.get("enable_circl", True):
        try:
            lookup_type = "sha256" if len(target_hash) == 64 else "md5"
            circl_url = f"https://hashlookup.circl.lu/lookup/{lookup_type}/{target_hash}"
            req = urllib.request.Request(circl_url, headers={"User-Agent": "AntigravityIntegrityScanner/2.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode('utf-8'))
                    if "KnownMalicious" in data:
                        res = {
                            "verdict": "MALICIOUS",
                            "details": f"CIRCL Flagged Malware: {data.get('KnownMalicious')}",
                            "source": "CIRCL Hashlookup"
                        }
                        cache[target_hash] = res
                        save_threat_intel_cache(cache)
                        return res
                    elif "FileName" in data or "NSRL" in str(data):
                        fname = data.get("FileName", "OS Component")
                        res = {
                            "verdict": "BENIGN",
                            "details": f"Verified Known OS Binary ({fname})",
                            "source": "CIRCL (NSRL)"
                        }
                        cache[target_hash] = res
                        save_threat_intel_cache(cache)
                        return res
        except Exception:
            pass # CIRCL returned 404 (not in database) or timed out

    # 3. Check MalwareBazaar (abuse.ch)
    if config.get("enable_malwarebazaar", True):
        try:
            mb_url = "https://mb-api.abuse.ch/api/v1/"
            post_data = urllib.parse.urlencode({"query": "get_info", "hash": target_hash}).encode('utf-8')
            req = urllib.request.Request(mb_url, data=post_data, headers={"User-Agent": "AntigravityIntegrityScanner/2.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get("query_status") == "ok":
                    first_hit = data.get("data", [{}])[0]
                    sig = first_hit.get("signature", "Generic Malware")
                    ftype = first_hit.get("file_type", "Executable")
                    res = {
                        "verdict": "MALICIOUS",
                        "details": f"MalwareBazaar: {sig} ({ftype})",
                        "source": "MalwareBazaar"
                    }
                    cache[target_hash] = res
                    save_threat_intel_cache(cache)
                    return res
        except Exception:
            pass

    # 4. Check VirusTotal (Only for unresolved files, rate-limit protected)
    vt_key = config.get("virustotal_api_key", "").strip()
    if vt_key and len(target_hash) in (32, 64):
        try:
            # Enforce 15-second pacing for the 4 calls/minute free tier limit
            rate_limit = config.get("rate_limit_seconds", 15)
            elapsed = time.time() - _LAST_VT_CALL
            if elapsed < rate_limit and _LAST_VT_CALL > 0:
                time.sleep(rate_limit - elapsed)

            _LAST_VT_CALL = time.time()
            vt_url = f"https://www.virustotal.com/api/v3/files/{target_hash}"
            req = urllib.request.Request(vt_url, headers={
                "x-apikey": vt_key,
                "User-Agent": "AntigravityIntegrityScanner/2.0"
            })
            with urllib.request.urlopen(req, timeout=12) as resp:
                if resp.status == 200:
                    vt_data = json.loads(resp.read().decode('utf-8'))
                    stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values())

                    if malicious > 0:
                        verdict = "MALICIOUS"
                        details = f"VirusTotal: {malicious}/{total} AV Detections"
                    elif suspicious > 0:
                        verdict = "SUSPICIOUS"
                        details = f"VirusTotal: {suspicious}/{total} Suspicious Flags"
                    else:
                        verdict = "BENIGN"
                        details = f"VirusTotal: Clean (0/{total} Detections)"

                    res = {
                        "verdict": verdict,
                        "details": details,
                        "source": "VirusTotal"
                    }
                    cache[target_hash] = res
                    save_threat_intel_cache(cache)
                    return res
        except urllib.error.HTTPError as e:
            if e.code == 404:
                res = {
                    "verdict": "UNKNOWN",
                    "details": "VirusTotal: Hash not seen before in VT database",
                    "source": "VirusTotal"
                }
                cache[target_hash] = res
                save_threat_intel_cache(cache)
                return res
        except Exception:
            pass

    return {"verdict": "UNKNOWN", "details": "Not listed in CIRCL/MalwareBazaar", "source": "None"}

def enrich_findings_with_threat_intel(comparison_data, config=None):
    """
    Enriches CRITICAL and HIGH severity findings using CIRCL, MalwareBazaar, and VirusTotal.
    Saves API quota by only investigating high-risk items.
    """
    cat = categorize_findings(comparison_data)
    candidates = cat['mod_binaries'] + cat['suid_findings'] + cat['suspicious_new']
    
    if not candidates:
        return
        
    if config is None:
        config = load_threat_intel_config()

    print(f"\n[*] Enriching {len(candidates)} Critical/High findings with Threat Intelligence...")
    print(f"    (CIRCL Hashlookup + MalwareBazaar" + (" + VirusTotal v3)" if config.get('virustotal_api_key') else ")"))

    cache = load_threat_intel_cache()
    for item in candidates:
        sha = item.get('target_sha256') or item.get('sha256_hash')
        md5 = item.get('target_md5') or item.get('md5_hash')
        
        intel = query_threat_intel(sha, md5_hash=md5, config=config, cache=cache)
        item['threat_verdict'] = intel.get('verdict', 'UNKNOWN')
        item['threat_details'] = intel.get('details', 'N/A')
        item['threat_source'] = intel.get('source', 'None')
        
        tag = f"[{item['threat_verdict']}]"
        print(f"    - {item.get('normalized_path')}: {tag} {item['threat_details']} ({item['threat_source']})")

def print_critical_report(comparison_data):
    """Display an executive terminal summary of critical security findings."""
    cat = categorize_findings(comparison_data)
    mod_bin = cat['mod_binaries']
    susp_new = cat['suspicious_new']
    suid_f = cat['suid_findings']
    summary = comparison_data.get('summary', {})

    print("\n" + "="*80)
    print("CRITICAL SECURITY FINDINGS REPORT".center(80))
    print("="*80)
    print(f"Analysis Time:  {comparison_data.get('analysis_timestamp', 'Unknown')}")
    print(f"Clean Baseline: {comparison_data.get('clean_scan_file', 'Unknown')}")
    print(f"Target Scan:    {comparison_data.get('target_scan_file', 'Unknown')}")
    print("-"*80)
    print(f"Total Files Analyzed (Clean / Target): {comparison_data.get('clean_total_files', 0):,} / {comparison_data.get('target_total_files', 0):,}")
    print(f"Differences: Modified={summary.get('modified_files_count', 0):,} | New={summary.get('new_files_count', 0):,} | Deleted={summary.get('deleted_files_count', 0):,}")
    print("-"*80)
    print("EXECUTIVE SECURITY SUMMARY")
    print(f"  [CRITICAL] SUID Privilege Escalations: {len(suid_f)}")
    print(f"  [CRITICAL] Modified System Binaries:   {len(mod_bin)}")
    print(f"  [HIGH]     Suspicious New Files:       {len(susp_new)}")
    print("="*80)

    if suid_f:
        print(f"\n[!] SUID PRIVILEGE ESCALATION DETECTED ({len(suid_f)} items):")
        print("    (File gained SUID root execution bit!)")
        print("-"*80)
        for i, f in enumerate(suid_f, 1):
            intel_disp = f" | [{f.get('threat_verdict')}] {f.get('threat_details')}" if f.get('threat_verdict') not in ('UNCHECKED', None) else ""
            print(f"[{i}] {f['normalized_path']} (Perms: {f.get('target_permissions')}){intel_disp}")

    if susp_new:
        print(f"\n1. SUSPICIOUS NEW FILES ({len(susp_new)} detected):")
        print("   (Executable extensions, drop zones, or hidden scripts)")
        print("-"*80)
        for i, f in enumerate(susp_new[:15], 1):
            intel_disp = f" | [{f.get('threat_verdict')}] {f.get('threat_details')}" if f.get('threat_verdict') not in ('UNCHECKED', None) else ""
            print(f"[{i}] {f['normalized_path']}")
            print(f"    Size:     {format_size(f.get('size_bytes'))}")
            print(f"    MD5:      {f.get('md5_hash')}")
            if f.get('sha256_hash') and f.get('sha256_hash') != 'N/A':
                print(f"    SHA-256:  {f.get('sha256_hash')}")
            if intel_disp:
                print(f"    Intel:   {intel_disp}")
            print(f"    Created:  {f.get('modification_datetime')}")
        if len(susp_new) > 15:
            print(f"    ... and {len(susp_new) - 15} more (see CSV / HTML reports).")

    if mod_bin:
        print(f"\n2. MODIFIED SYSTEM BINARIES ({len(mod_bin)} detected):")
        print("   (Hash mismatch in system executable directories - potential tampering!)")
        print("-"*80)
        for i, f in enumerate(mod_bin[:15], 1):
            intel_disp = f" | [{f.get('threat_verdict')}] {f.get('threat_details')}" if f.get('threat_verdict') not in ('UNCHECKED', None) else ""
            print(f"[{i}] {f['normalized_path']}")
            print(f"    Clean MD5:  {f.get('clean_md5')}")
            print(f"    Target MD5: {f.get('target_md5')}")
            if f.get('target_sha256') and f.get('target_sha256') != 'N/A':
                print(f"    Target SHA: {f.get('target_sha256')}")
            if intel_disp:
                print(f"    Intel:     {intel_disp}")
        if len(mod_bin) > 15:
            print(f"    ... and {len(mod_bin) - 15} more (see CSV / HTML reports).")

    if not susp_new and not mod_bin and not suid_f:
        print("\n[+] Clean check! No modified binaries or suspicious new files detected.")
    print("="*80 + "\n")

# ----------------------------------------------------------------------
# 5. CSV & Interactive HTML Reporting
# ----------------------------------------------------------------------

def generate_csv_report(comparison_data, output_csv):
    """Exports structured findings into a CSV report with severity and threat intel tags."""
    cat = categorize_findings(comparison_data)
    rows = []

    # 1. SUID Escalations
    for f in cat['suid_findings']:
        rows.append({
            'Category': 'SUID Privilege Escalation',
            'Suggested Severity': 'CRITICAL',
            'Path': f['normalized_path'],
            'Status': 'Modified (SUID)',
            'Size': f.get('target_size', 0),
            'Threat Intel Verdict': f.get('threat_verdict', 'N/A'),
            'Threat Intel Details': f.get('threat_details', 'N/A'),
            'Clean MD5': f.get('clean_md5', 'Unknown'),
            'Target MD5': f.get('target_md5', 'Unknown'),
            'Clean SHA256': f.get('clean_sha256', 'N/A'),
            'Target SHA256': f.get('target_sha256', 'N/A'),
            'Modification Time': f.get('target_modification_time', 'Unknown')
        })

    # 2. Suspicious New Files
    for f in cat['suspicious_new']:
        sev = 'CRITICAL' if is_system_binary(f['normalized_path']) else 'HIGH'
        rows.append({
            'Category': 'Suspicious New File',
            'Suggested Severity': sev,
            'Path': f['normalized_path'],
            'Status': 'New',
            'Size': f.get('size_bytes', 0),
            'Threat Intel Verdict': f.get('threat_verdict', 'N/A'),
            'Threat Intel Details': f.get('threat_details', 'N/A'),
            'Clean MD5': 'N/A',
            'Target MD5': f.get('md5_hash', 'Unknown'),
            'Clean SHA256': 'N/A',
            'Target SHA256': f.get('sha256_hash', 'N/A'),
            'Modification Time': f.get('modification_datetime', 'Unknown')
        })

    # 3. Modified System Binaries
    for f in cat['mod_binaries']:
        rows.append({
            'Category': 'Modified System Binary',
            'Suggested Severity': 'CRITICAL',
            'Path': f['normalized_path'],
            'Status': 'Modified',
            'Size': f.get('target_size', 0),
            'Threat Intel Verdict': f.get('threat_verdict', 'N/A'),
            'Threat Intel Details': f.get('threat_details', 'N/A'),
            'Clean MD5': f.get('clean_md5', 'Unknown'),
            'Target MD5': f.get('target_md5', 'Unknown'),
            'Clean SHA256': f.get('clean_sha256', 'N/A'),
            'Target SHA256': f.get('target_sha256', 'N/A'),
            'Modification Time': f.get('target_modification_time', 'Unknown')
        })

    # 4. Other Modified Files
    for f in cat['other_modified']:
        rows.append({
            'Category': 'Modified File',
            'Suggested Severity': 'MEDIUM',
            'Path': f['normalized_path'],
            'Status': 'Modified',
            'Size': f.get('target_size', 0),
            'Threat Intel Verdict': f.get('threat_verdict', 'N/A'),
            'Threat Intel Details': f.get('threat_details', 'N/A'),
            'Clean MD5': f.get('clean_md5', 'Unknown'),
            'Target MD5': f.get('target_md5', 'Unknown'),
            'Clean SHA256': f.get('clean_sha256', 'N/A'),
            'Target SHA256': f.get('target_sha256', 'N/A'),
            'Modification Time': f.get('target_modification_time', 'Unknown')
        })

    # 5. Other New Files
    for f in cat['other_new']:
        rows.append({
            'Category': 'New File',
            'Suggested Severity': 'LOW',
            'Path': f['normalized_path'],
            'Status': 'New',
            'Size': f.get('size_bytes', 0),
            'Threat Intel Verdict': f.get('threat_verdict', 'N/A'),
            'Threat Intel Details': f.get('threat_details', 'N/A'),
            'Clean MD5': 'N/A',
            'Target MD5': f.get('md5_hash', 'Unknown'),
            'Clean SHA256': 'N/A',
            'Target SHA256': f.get('sha256_hash', 'N/A'),
            'Modification Time': f.get('modification_datetime', 'Unknown')
        })

    # 6. Deleted Files
    for f in cat['deleted']:
        rows.append({
            'Category': 'Deleted File',
            'Suggested Severity': 'MEDIUM',
            'Path': f['normalized_path'],
            'Status': 'Deleted',
            'Size': f.get('size_bytes', 0),
            'Threat Intel Verdict': 'N/A',
            'Threat Intel Details': 'Deleted from target',
            'Clean MD5': f.get('md5_hash', 'Unknown'),
            'Target MD5': 'N/A',
            'Clean SHA256': f.get('sha256_hash', 'N/A'),
            'Target SHA256': 'N/A',
            'Modification Time': f.get('modification_datetime', 'Unknown')
        })

    fieldnames = [
        'Category', 'Suggested Severity', 'Path', 'Status',
        'Size', 'Threat Intel Verdict', 'Threat Intel Details',
        'Clean MD5', 'Target MD5', 'Clean SHA256', 'Target SHA256', 'Modification Time'
    ]

    os.makedirs(os.path.dirname(os.path.abspath(output_csv)), exist_ok=True)
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Successfully exported {len(rows):,} findings to CSV: {output_csv}")

def generate_html_report(comparison_data, output_html):
    """
    Generates a modern, self-contained, interactive HTML dashboard report
    with embedded client-side search, severity filters, threat intel badges, and responsive styling.
    Zero external dependencies (requires no internet connection or CDN).
    """
    cat = categorize_findings(comparison_data)
    summary = comparison_data.get('summary', {})
    mod_count = summary.get('modified_files_count', 0)
    new_count = summary.get('new_files_count', 0)
    del_count = summary.get('deleted_files_count', 0)
    
    crit_count = len(cat['mod_binaries']) + len(cat['suid_findings'])
    high_count = len(cat['suspicious_new'])
    total_diffs = mod_count + new_count + del_count

    table_rows = []

    # SUID Findings
    for f in cat['suid_findings']:
        table_rows.append({
            'category': 'SUID Escalation',
            'severity': 'CRITICAL',
            'status': 'Modified (SUID)',
            'threat': f.get('threat_verdict', 'N/A'),
            'threat_detail': f.get('threat_details', 'N/A'),
            'path': f['normalized_path'],
            'size': format_size(f.get('target_size', 0)),
            'target_hash': f.get('target_sha256', f.get('target_md5', 'N/A')),
            'clean_hash': f.get('clean_sha256', f.get('clean_md5', 'N/A')),
            'time': f.get('target_modification_time', 'N/A')
        })

    # Modified System Binaries
    for f in cat['mod_binaries']:
        table_rows.append({
            'category': 'Modified Binary',
            'severity': 'CRITICAL',
            'status': 'Modified',
            'threat': f.get('threat_verdict', 'N/A'),
            'threat_detail': f.get('threat_details', 'N/A'),
            'path': f['normalized_path'],
            'size': format_size(f.get('target_size', 0)),
            'target_hash': f.get('target_sha256', f.get('target_md5', 'N/A')),
            'clean_hash': f.get('clean_sha256', f.get('clean_md5', 'N/A')),
            'time': f.get('target_modification_time', 'N/A')
        })

    # Suspicious New Files
    for f in cat['suspicious_new']:
        sev = 'CRITICAL' if is_system_binary(f['normalized_path']) else 'HIGH'
        table_rows.append({
            'category': 'Suspicious Script/File',
            'severity': sev,
            'status': 'New',
            'threat': f.get('threat_verdict', 'N/A'),
            'threat_detail': f.get('threat_details', 'N/A'),
            'path': f['normalized_path'],
            'size': format_size(f.get('size_bytes', 0)),
            'target_hash': f.get('sha256_hash', f.get('md5_hash', 'N/A')),
            'clean_hash': 'N/A',
            'time': f.get('modification_datetime', 'N/A')
        })

    # Other Modified Files
    for f in cat['other_modified']:
        table_rows.append({
            'category': 'Modified File',
            'severity': 'MEDIUM',
            'status': 'Modified',
            'threat': f.get('threat_verdict', 'N/A'),
            'threat_detail': f.get('threat_details', 'N/A'),
            'path': f['normalized_path'],
            'size': format_size(f.get('target_size', 0)),
            'target_hash': f.get('target_sha256', f.get('target_md5', 'N/A')),
            'clean_hash': f.get('clean_sha256', f.get('clean_md5', 'N/A')),
            'time': f.get('target_modification_time', 'N/A')
        })

    # Other New Files
    for f in cat['other_new']:
        table_rows.append({
            'category': 'New File',
            'severity': 'LOW',
            'status': 'New',
            'threat': f.get('threat_verdict', 'N/A'),
            'threat_detail': f.get('threat_details', 'N/A'),
            'path': f['normalized_path'],
            'size': format_size(f.get('size_bytes', 0)),
            'target_hash': f.get('sha256_hash', f.get('md5_hash', 'N/A')),
            'clean_hash': 'N/A',
            'time': f.get('modification_datetime', 'N/A')
        })

    # Deleted Files
    for f in cat['deleted']:
        table_rows.append({
            'category': 'Deleted File',
            'severity': 'MEDIUM',
            'status': 'Deleted',
            'threat': 'N/A',
            'threat_detail': 'Deleted from target',
            'path': f['normalized_path'],
            'size': format_size(f.get('size_bytes', 0)),
            'target_hash': 'N/A',
            'clean_hash': f.get('sha256_hash', f.get('md5_hash', 'N/A')),
            'time': f.get('modification_datetime', 'N/A')
        })

    rows_json = json.dumps(table_rows)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Filesystem Integrity & Threat Intel Audit Report</title>
<style>
  :root {{
    --bg-main: #0d1117;
    --bg-card: #161b22;
    --bg-header: #21262d;
    --border: #30363d;
    --text-primary: #c9d1d9;
    --text-muted: #8b949e;
    --accent: #58a6ff;
    --crit: #f85149;
    --high: #d29922;
    --med: #e3b341;
    --low: #3fb950;
    --badge-bg: #21262d;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-primary);
    padding: 24px;
    line-height: 1.5;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  header {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 24px;
  }}
  h1 {{ font-size: 1.8rem; color: #fff; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 12px;
    font-size: 0.88rem;
    color: var(--text-muted);
    margin-top: 14px;
  }}
  .meta-grid span strong {{ color: var(--text-primary); }}
  
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }}
  .kpi-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .kpi-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 4px;
  }}
  .kpi-card.crit::before {{ background: var(--crit); }}
  .kpi-card.high::before {{ background: var(--high); }}
  .kpi-card.mod::before {{ background: var(--med); }}
  .kpi-card.new::before {{ background: var(--low); }}
  .kpi-card.del::before {{ background: var(--text-muted); }}

  .kpi-value {{ font-size: 2rem; font-weight: 700; color: #fff; margin: 4px 0; }}
  .kpi-label {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }}

  .controls {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px 8px 0 0;
    padding: 16px;
    align-items: center;
  }}
  .search-box {{
    flex: 1;
    min-width: 250px;
    position: relative;
  }}
  .search-box input {{
    width: 100%;
    background: var(--bg-main);
    border: 1px solid var(--border);
    color: #fff;
    padding: 8px 14px;
    border-radius: 6px;
    font-size: 0.9rem;
  }}
  .select-box select {{
    background: var(--bg-main);
    border: 1px solid var(--border);
    color: #fff;
    padding: 8px 14px;
    border-radius: 6px;
    font-size: 0.9rem;
    cursor: pointer;
  }}
  .count-indicator {{
    font-size: 0.85rem;
    color: var(--text-muted);
    margin-left: auto;
  }}

  .table-container {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-top: none;
    border-radius: 0 0 8px 8px;
    overflow-x: auto;
    max-height: 700px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    text-align: left;
  }}
  th {{
    background: var(--bg-header);
    color: var(--text-muted);
    font-weight: 600;
    padding: 12px 16px;
    position: sticky;
    top: 0;
    z-index: 10;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }}
  td {{
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }}
  tr:hover {{ background-color: rgba(88, 166, 255, 0.04); }}
  
  .badge {{
    display: inline-block;
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
  }}
  .badge-CRITICAL {{ background: rgba(248, 81, 73, 0.2); color: var(--crit); border: 1px solid var(--crit); }}
  .badge-HIGH {{ background: rgba(210, 153, 34, 0.2); color: var(--high); border: 1px solid var(--high); }}
  .badge-MEDIUM {{ background: rgba(227, 179, 65, 0.2); color: var(--med); border: 1px solid var(--med); }}
  .badge-LOW {{ background: rgba(63, 185, 80, 0.2); color: var(--low); border: 1px solid var(--low); }}

  .badge-MALICIOUS {{ background: rgba(248, 81, 73, 0.25); color: #ff7b72; border: 1px solid #ff7b72; }}
  .badge-SUSPICIOUS {{ background: rgba(210, 153, 34, 0.25); color: #e3b341; border: 1px solid #e3b341; }}
  .badge-BENIGN {{ background: rgba(63, 185, 80, 0.25); color: #56d364; border: 1px solid #56d364; }}
  .badge-UNKNOWN {{ background: rgba(139, 148, 158, 0.2); color: var(--text-muted); border: 1px solid var(--text-muted); }}

  .hash-code {{
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 0.76rem;
    background: var(--bg-main);
    padding: 2px 6px;
    border-radius: 4px;
    color: #e6edf3;
    display: inline-block;
    max-width: 250px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }}
  .path-cell {{
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 0.82rem;
    word-break: break-all;
    max-width: 400px;
  }}
</style>
</head>
<body>

<div class="container">
  <header>
    <h1>🛡️ Filesystem Integrity & Threat Intel Audit Report</h1>
    <div class="meta-grid">
      <span><strong>Analysis Timestamp:</strong> {comparison_data.get('analysis_timestamp', 'Unknown')}</span>
      <span><strong>Clean Baseline:</strong> {os.path.basename(str(comparison_data.get('clean_scan_file', '')))}</span>
      <span><strong>Target Scan:</strong> {os.path.basename(str(comparison_data.get('target_scan_file', '')))}</span>
      <span><strong>Files Indexed:</strong> {comparison_data.get('clean_total_files', 0):,} Clean | {comparison_data.get('target_total_files', 0):,} Target</span>
    </div>
  </header>

  <div class="kpi-grid">
    <div class="kpi-card crit">
      <div class="kpi-label">Critical Findings</div>
      <div class="kpi-value" style="color: var(--crit);">{crit_count}</div>
      <small style="color: var(--text-muted);">Binaries & SUID</small>
    </div>
    <div class="kpi-card high">
      <div class="kpi-label">Suspicious Files</div>
      <div class="kpi-value" style="color: var(--high);">{high_count}</div>
      <small style="color: var(--text-muted);">Drop zones & scripts</small>
    </div>
    <div class="kpi-card mod">
      <div class="kpi-label">Modified Files</div>
      <div class="kpi-value">{mod_count:,}</div>
      <small style="color: var(--text-muted);">Hash mismatches</small>
    </div>
    <div class="kpi-card new">
      <div class="kpi-label">New Files</div>
      <div class="kpi-value">{new_count:,}</div>
      <small style="color: var(--text-muted);">Target-only files</small>
    </div>
    <div class="kpi-card del">
      <div class="kpi-label">Deleted Files</div>
      <div class="kpi-value">{del_count:,}</div>
      <small style="color: var(--text-muted);">Baseline-only files</small>
    </div>
  </div>

  <div class="controls">
    <div class="search-box">
      <input type="text" id="searchInput" placeholder="Search paths, filenames, hashes, threat details..." onkeyup="filterData()">
    </div>
    <div class="select-box">
      <select id="severityFilter" onchange="filterData()">
        <option value="ALL">All Severities</option>
        <option value="CRITICAL">Critical Only</option>
        <option value="HIGH">High Only</option>
        <option value="MEDIUM">Medium Only</option>
        <option value="LOW">Low Only</option>
      </select>
    </div>
    <div class="select-box">
      <select id="threatFilter" onchange="filterData()">
        <option value="ALL">All Threat Verdicts</option>
        <option value="MALICIOUS">Malicious Only</option>
        <option value="SUSPICIOUS">Suspicious Only</option>
        <option value="BENIGN">Benign Only</option>
      </select>
    </div>
    <div class="select-box">
      <select id="statusFilter" onchange="filterData()">
        <option value="ALL">All Statuses</option>
        <option value="Modified">Modified</option>
        <option value="New">New</option>
        <option value="Deleted">Deleted</option>
      </select>
    </div>
    <div class="count-indicator" id="rowCount">Showing {total_diffs:,} records</div>
  </div>

  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Threat Intel</th>
          <th>Category</th>
          <th>Normalized Path</th>
          <th>Status</th>
          <th>Size</th>
          <th>Target Hash</th>
          <th>Baseline Hash</th>
          <th>Modification Date</th>
        </tr>
      </thead>
      <tbody id="tableBody"></tbody>
    </table>
  </div>
</div>

<script>
  const data = {rows_json};

  function renderTable(items) {{
    const tbody = document.getElementById('tableBody');
    if (items.length === 0) {{
      tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 40px; color: var(--text-muted);">No matching entries found.</td></tr>';
      document.getElementById('rowCount').innerText = 'Showing 0 records';
      return;
    }}

    const renderLimit = 1000;
    const slice = items.slice(0, renderLimit);
    
    let html = '';
    for (let i = 0; i < slice.length; i++) {{
      const r = slice[i];
      const threatBadge = r.threat && r.threat !== 'N/A' && r.threat !== 'UNCHECKED'
        ? `<span class="badge badge-${{r.threat}}" title="${{r.threat_detail}}">${{r.threat}}</span><br><small style="color:var(--text-muted);font-size:0.75rem;">${{r.threat_detail}}</small>`
        : '<span style="color:var(--text-muted);font-size:0.78rem;">-</span>';

      html += `<tr>
        <td><span class="badge badge-${{r.severity}}">${{r.severity}}</span></td>
        <td>${{threatBadge}}</td>
        <td>${{r.category}}</td>
        <td class="path-cell" title="${{r.path}}">${{r.path}}</td>
        <td>${{r.status}}</td>
        <td>${{r.size}}</td>
        <td><span class="hash-code" title="${{r.target_hash}}">${{r.target_hash}}</span></td>
        <td><span class="hash-code" title="${{r.clean_hash}}">${{r.clean_hash}}</span></td>
        <td style="white-space: nowrap; font-size: 0.78rem;">${{r.time}}</td>
      </tr>`;
    }}
    tbody.innerHTML = html;
    const suffix = items.length > renderLimit ? ` (capped at ${{renderLimit}} for speed)` : '';
    document.getElementById('rowCount').innerText = `Showing ${{items.length.toLocaleString()}} records${{suffix}}`;
  }}

  function filterData() {{
    const query = document.getElementById('searchInput').value.toLowerCase().trim();
    const sev = document.getElementById('severityFilter').value;
    const thr = document.getElementById('threatFilter').value;
    const stat = document.getElementById('statusFilter').value;

    const filtered = data.filter(r => {{
      const matchQuery = !query || r.path.toLowerCase().includes(query) || r.target_hash.toLowerCase().includes(query) || r.category.toLowerCase().includes(query) || (r.threat_detail && r.threat_detail.toLowerCase().includes(query));
      const matchSev = (sev === 'ALL') || (r.severity === sev);
      const matchThr = (thr === 'ALL') || (r.threat === thr);
      const matchStat = (stat === 'ALL') || (r.status.startsWith(stat));
      return matchQuery && matchSev && matchThr && matchStat;
    }});

    renderTable(filtered);
  }}

  renderTable(data);
</script>
</body>
</html>
"""
    os.makedirs(os.path.dirname(os.path.abspath(output_html)), exist_ok=True)
    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[+] Successfully generated Interactive HTML Report: {output_html}")

# ----------------------------------------------------------------------
# 6. Baseline File Discovery
# ----------------------------------------------------------------------

def find_clean_json():
    """Locates clean.json or clean.json.gz in current directory or clean/ subdirectories."""
    candidates = ["clean.json", "clean.json.gz"]
    for c in candidates:
        if os.path.exists(c):
            print(f"[+] Found baseline '{c}' in current directory.")
            return c

    # Check clean/baseline/
    for c in candidates:
        sub_p = os.path.join("clean", "baseline", c)
        if os.path.exists(sub_p):
            print(f"[+] Found baseline at: {sub_p}")
            return sub_p

    # Recursive search in clean folder
    if os.path.exists("clean"):
        for root, dirs, files in os.walk("clean"):
            for f in files:
                if f in ("clean.json", "clean.json.gz"):
                    found = os.path.join(root, f)
                    print(f"[+] Found baseline at: {found}")
                    return found

    return None

# ----------------------------------------------------------------------
# 7. Workflow Procedures
# ----------------------------------------------------------------------

def workflow_baseline_scan(scan_path=None, compress=False, max_file_mb=None):
    """Creates a fresh baseline scan snapshot."""
    print("\n" + "="*70)
    print("STEP 1: CREATING BASELINE SNAPSHOT (CLEAN STATE)".center(70))
    print("="*70)
    out_file = scan_filesystem(start_path=scan_path, compress=compress, max_file_mb=max_file_mb)
    if out_file and os.path.exists(out_file):
        dest_name = "clean.json.gz" if (compress or out_file.endswith(".gz")) else "clean.json"
        shutil.copy2(out_file, dest_name)
        print(f"\n[+] Baseline snapshot created and saved as '{dest_name}' in current directory.")
        return dest_name
    else:
        print("\n[-] Error: Failed to generate baseline scan.")
        return None

def workflow_target_scan_and_compare(baseline_path=None, scan_path=None, compress=False, max_file_mb=None, skip_intel=False):
    """Runs target scan, compares against baseline, enriches with Threat Intel, and outputs CSV + HTML reports."""
    print("\n" + "="*70)
    print("STEP 2: SCANNING TARGET SYSTEM & COMPARING WITH BASELINE".center(70))
    print("="*70)

    if not baseline_path:
        baseline_path = find_clean_json()

    if not baseline_path:
        print("[-] Error: Baseline scan 'clean.json' or 'clean.json.gz' not found!")
        print("    Please run Option 1 first to create clean.json, or supply a baseline path.")
        return

    print(f"[*] Active Baseline: {baseline_path}")
    target_scan_file = scan_filesystem(start_path=scan_path, verbose=True, compress=compress, max_file_mb=max_file_mb)
    if not target_scan_file or not os.path.exists(target_scan_file):
        print("[-] Target scan failed.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outcome_dir = os.path.join(os.getcwd(), f"scan_results_{timestamp}")
    os.makedirs(outcome_dir, exist_ok=True)

    ext = ".json.gz" if (compress or target_scan_file.endswith(".gz")) else ".json"
    target_json = os.path.join(outcome_dir, f"target{ext}")
    compare_json = os.path.join(outcome_dir, f"compare{ext}")
    csv_report = os.path.join(outcome_dir, "critical_findings.csv")
    html_report = os.path.join(outcome_dir, "findings_report.html")

    shutil.copy2(target_scan_file, target_json)
    print(f"\n[+] Saved target scan to: {target_json}")

    print(f"[*] Comparing target scan against baseline...")
    comparison = compare_scans(baseline_path, target_json, output_file=compare_json)
    if not comparison:
        print("[-] Comparison failed.")
        return

    if not skip_intel:
        enrich_findings_with_threat_intel(comparison)

    print(f"[+] Diff comparison saved to: {compare_json}")
    generate_csv_report(comparison, csv_report)
    generate_html_report(comparison, html_report)
    print_critical_report(comparison)

    print(f"[*] All results stored in folder: {outcome_dir}")
    print(f"[*] Open HTML Report in browser: file:///{os.path.abspath(html_report).replace(os.sep, '/')}")

def workflow_compare_existing(clean_path, target_path, output_csv=None, output_json=None, output_html=None, skip_intel=False):
    """Directly compares two existing scan JSON files, enriches with Threat Intel, and outputs CSV + HTML reports."""
    print("\n" + "="*70)
    print("COMPARING EXISTING SCAN FILES".center(70))
    print(f"Clean:  {clean_path}")
    print(f"Target: {target_path}")
    print("="*70)

    if not output_json:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_json = f"compare_{timestamp}.json"

    comparison = compare_scans(clean_path, target_path, output_file=output_json)
    if not comparison:
        return

    if not skip_intel:
        enrich_findings_with_threat_intel(comparison)

    if not output_csv:
        output_csv = output_json.replace(".json.gz", "").replace(".json", "") + "_findings.csv"
    if not output_html:
        output_html = output_json.replace(".json.gz", "").replace(".json", "") + "_report.html"

    generate_csv_report(comparison, output_csv)
    generate_html_report(comparison, output_html)
    print_critical_report(comparison)
    print(f"[*] Open HTML Report in browser: file:///{os.path.abspath(output_html).replace(os.sep, '/')}")

def view_json_summary(file_path):
    """Quick console viewer for scan or comparison JSON files."""
    data = load_json_scan(file_path)
    if not data:
        return

    print("\n" + "="*70)
    print(f"INSPECTING: {file_path}".center(70))
    print("="*70)

    if isinstance(data, list):
        print(f"Type: Raw Filesystem Scan")
        print(f"Total Files Indexed: {len(data):,}")
        print("\nSample Entries (First 5):")
        for item in data[:5]:
            sha = item.get('sha256_hash', 'N/A')
            sha_disp = f" | SHA256: {sha[:16]}..." if sha != 'N/A' else ""
            print(f"  - {item.get('full_path')} | {format_size(item.get('size_bytes'))} | MD5: {item.get('md5_hash')}{sha_disp}")
    elif isinstance(data, dict) and 'summary' in data:
        summary = data['summary']
        print("Type: Comparison Results")
        print(f"Analysis Time:  {data.get('analysis_timestamp')}")
        print(f"Modified Files: {summary.get('modified_files_count', 0):,}")
        print(f"New Files:      {summary.get('new_files_count', 0):,}")
        print(f"Deleted Files:  {summary.get('deleted_files_count', 0):,}")
        print_critical_report(data)
    else:
        print("Unknown JSON format.")

# ----------------------------------------------------------------------
# 8. Interactive Menu & CLI Dispatcher
# ----------------------------------------------------------------------

def interactive_menu():
    while True:
        print("\n" + "="*75)
        print("UNIFIED FILESYSTEM SCANNER AND INTEGRITY CHECKER (v2.0)".center(75))
        print("="*75)
        print("  1. Create Clean Baseline Scan (clean.json or clean.json.gz)")
        print("  2. Scan Target, Compare with Baseline, and Generate CSV + HTML Reports")
        print("  3. Scan Baseline & Target Sequentially (Benchmark / Demo)")
        print("  4. Compare Two Existing JSON Scan Files (Generate Reports)")
        print("  5. Inspect / View a Scan or Comparison JSON File")
        print("  6. Export Interactive HTML Report from an Existing Diff JSON")
        print("  7. Exit")
        print("="*75)

        try:
            choice = input("\nEnter your choice (1-7): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting... Goodbye!")
            break

        if choice == '1':
            custom = input("Enter path to scan (or press Enter for default root): ").strip()
            compress = input("Enable Gzip compression to save 85% disk space? [y/N]: ").strip().lower() == 'y'
            workflow_baseline_scan(scan_path=custom if custom else None, compress=compress)
        elif choice == '2':
            custom = input("Enter path to scan (or press Enter for default root): ").strip()
            compress = input("Enable Gzip compression? [y/N]: ").strip().lower() == 'y'
            workflow_target_scan_and_compare(scan_path=custom if custom else None, compress=compress)
        elif choice == '3':
            clean_file = workflow_baseline_scan()
            if clean_file:
                time.sleep(1)
                workflow_target_scan_and_compare(baseline_path=clean_file)
        elif choice == '4':
            clean_p = input("Enter path to clean baseline JSON (.json or .json.gz): ").strip()
            target_p = input("Enter path to target JSON (.json or .json.gz): ").strip()
            if os.path.exists(clean_p) and os.path.exists(target_p):
                workflow_compare_existing(clean_p, target_p)
            else:
                print("[-] One or both paths are invalid.")
        elif choice == '5':
            view_p = input("Enter path to JSON file to view: ").strip()
            if os.path.exists(view_p):
                view_json_summary(view_p)
            else:
                print(f"[-] File not found: {view_p}")
        elif choice == '6':
            diff_p = input("Enter path to comparison JSON (.json or .json.gz): ").strip()
            if os.path.exists(diff_p):
                data = load_json_scan(diff_p)
                if data and isinstance(data, dict) and 'summary' in data:
                    out_html = diff_p.replace(".json.gz", "").replace(".json", "") + "_report.html"
                    generate_html_report(data, out_html)
                    print(f"[*] Open report: file:///{os.path.abspath(out_html).replace(os.sep, '/')}")
                else:
                    print("[-] Specified file is not a valid comparison JSON.")
            else:
                print(f"[-] File not found: {diff_p}")
        elif choice in ('7', 'exit', 'quit'):
            print("\nExiting... Goodbye!")
            break
        else:
            print("\n[-] Invalid option. Please select 1 through 7.")

def main():
    parser = argparse.ArgumentParser(
        description="Unified Filesystem Scanner and Integrity Checker (v2.0 Forensic Edition)"
    )
    parser.add_argument("--baseline", action="store_true", help="Create baseline scan (clean.json or clean.json.gz)")
    parser.add_argument("--target", action="store_true", help="Scan target and compare against clean baseline")
    parser.add_argument("--compare", nargs=2, metavar=('CLEAN_JSON', 'TARGET_JSON'), help="Compare two scan JSON files")
    parser.add_argument("--view", metavar="JSON_FILE", help="View summary of a scan or comparison JSON")
    parser.add_argument("--path", help="Custom path to scan (defaults to C:\\ or /)")
    parser.add_argument("--compress", action="store_true", help="Save scan snapshots with Gzip compression (.json.gz)")
    parser.add_argument("--max-size-mb", type=float, help="Cap hash hashing at max MB per file (skips massive ISO/VMDK)")
    parser.add_argument("--skip-intel", action="store_true", help="Skip Threat Intelligence lookups (offline mode)")
    parser.add_argument("--vt-key", help="Override VirusTotal API key")
    parser.add_argument("--output-csv", help="Custom path for output CSV report")
    parser.add_argument("--output-html", help="Custom path for interactive HTML dashboard")
    parser.add_argument("--output-json", help="Custom path for output comparison JSON")

    args = parser.parse_args()

    # CLI Dispatch
    if args.baseline:
        workflow_baseline_scan(scan_path=args.path, compress=args.compress, max_file_mb=args.max_size_mb)
    elif args.target:
        workflow_target_scan_and_compare(scan_path=args.path, compress=args.compress, max_file_mb=args.max_size_mb, skip_intel=args.skip_intel)
    elif args.compare:
        workflow_compare_existing(
            args.compare[0],
            args.compare[1],
            output_csv=args.output_csv,
            output_json=args.output_json,
            output_html=args.output_html,
            skip_intel=args.skip_intel
        )
    elif args.view:
        view_json_summary(args.view)
    else:
        interactive_menu()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
