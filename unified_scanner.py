#!/usr/bin/env python3
"""
================================================================================
UNIFIED FILESYSTEM SCANNER AND INTEGRITY CHECKER
================================================================================
An agentless, cross-platform filesystem auditing tool designed for malware detection,
system integrity monitoring, and forensic analysis.

Features:
- Fast parallel chunked MD5 hashing (multiprocessing)
- Cross-username path normalization (/home/user -> /home/USER, C:\\Users\\user -> C:\\Users\\USER)
- Critical threat classification (modified binaries, suspicious scripts, drop zones)
- Automated CSV threat report generation and JSON diffing
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
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# ----------------------------------------------------------------------
# 1. Hashing & Filesystem Scanning Engine
# ----------------------------------------------------------------------

def calculate_md5(file_path):
    """Calculate MD5 hash of a file using 128KB chunks for optimal I/O throughput."""
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(131072), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except (PermissionError, OSError, IOError):
        return None

def process_file_task(file_path):
    """Worker task executed by parallel worker processes."""
    try:
        stats = os.stat(file_path)
        file_size = stats.st_size
        
        # Skip empty files
        if file_size == 0:
            return None
            
        md5_hash = calculate_md5(file_path)
        if md5_hash:
            return {
                "filename": os.path.basename(file_path),
                "full_path": file_path,
                "modification_datetime": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "md5_hash": md5_hash,
                "size_bytes": file_size
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

def save_json(output_file, data):
    """Save data as formatted JSON with UTF-8 encoding."""
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def scan_filesystem(start_path=None, output_file=None, verbose=True):
    """
    Recursively scans the filesystem using parallel multiprocessing to hash files.
    """
    if start_path is None:
        start_path = "C:\\" if os.name == "nt" else "/"

    hostname = socket.gethostname()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_file is None:
        output_file = os.path.join(os.getcwd(), f"filesystem_scan_{timestamp}.json")

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

    print("\n" + "-"*70)
    print(f"[*] Starting parallel filesystem scan: {start_path}")
    print(f"[*] Hostname:    {hostname}")
    print(f"[*] Workers:     {max_workers} CPU cores")
    print(f"[*] Output file: {output_file}")
    print("-"*70 + "\n")

    tasks = []
    try:
        print("[*] Enumerating files...", end='\r')
        for root, dirs, files in os.walk(start_path, topdown=True):
            # Prune skipped directories
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in files:
                tasks.append(os.path.join(root, filename))

        total_tasks = len(tasks)
        print(f"[*] Found {total_tasks:,} files to analyze. Starting parallel hashing...".ljust(80))

        chunk_size = 2000
        processed_total = 0

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            for chunk_start in range(0, total_tasks, chunk_size):
                chunk_end = min(chunk_start + chunk_size, total_tasks)
                chunk_tasks = tasks[chunk_start:chunk_end]

                future_to_file = {executor.submit(process_file_task, f): f for f in chunk_tasks}

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
                            save_json(output_file, results)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user! Saving partial results...")

    total_time = time.time() - start_time
    save_json(output_file, results)

    print(f"\n[+] Scan finished!")
    print(f"    - Total files indexed: {len(results):,}")
    print(f"    - Total time elapsed:  {format_time(total_time)}")
    print(f"    - Saved snapshot:      {output_file}\n")
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

def load_json_scan(file_path):
    """Loads and validates a filesystem scan JSON file."""
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' does not exist.")
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Error parsing JSON in '{file_path}': {e}")
        return None

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
    Identifies modified, new, and deleted files with cross-username normalization.
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
            if target_info.get('md5_hash') != clean_info.get('md5_hash'):
                modified_files.append({
                    'normalized_path': norm_path,
                    'clean_system_path': clean_info.get('full_path'),
                    'target_system_path': target_info.get('full_path'),
                    'filename': target_info.get('filename'),
                    'clean_md5': clean_info.get('md5_hash'),
                    'target_md5': target_info.get('md5_hash'),
                    'clean_modification_time': clean_info.get('modification_datetime'),
                    'target_modification_time': target_info.get('modification_datetime'),
                    'clean_size': clean_info.get('size_bytes', 'N/A'),
                    'target_size': target_info.get('size_bytes', 'N/A')
                })
        else:
            new_files.append({
                'normalized_path': norm_path,
                'target_system_path': target_info.get('full_path'),
                'filename': target_info.get('filename'),
                'md5_hash': target_info.get('md5_hash'),
                'modification_datetime': target_info.get('modification_datetime'),
                'size_bytes': target_info.get('size_bytes', 'N/A')
            })

    # Check for deleted files
    for norm_path, clean_info in clean_dict.items():
        if norm_path not in target_dict:
            deleted_files.append({
                'normalized_path': norm_path,
                'clean_system_path': clean_info.get('full_path'),
                'filename': clean_info.get('filename'),
                'md5_hash': clean_info.get('md5_hash'),
                'modification_datetime': clean_info.get('modification_datetime'),
                'size_bytes': clean_info.get('size_bytes', 'N/A')
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
# 3. Threat Classification & Reporting
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
    """Detect suspicious executable extensions, hidden scripts, or drop zones."""
    path = file_info.get('normalized_path', '')
    path_lower = path.lower()
    filename = file_info.get('filename', '')
    filename_lower = filename.lower()

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
    other_modified = []
    other_new = []

    for f in modified:
        if is_system_binary(f['normalized_path']):
            mod_binaries.append(f)
        else:
            other_modified.append(f)

    for f in new:
        if is_suspicious_file(f):
            suspicious_new.append(f)
        else:
            other_new.append(f)

    return {
        'mod_binaries': mod_binaries,
        'suspicious_new': suspicious_new,
        'other_modified': other_modified,
        'other_new': other_new,
        'deleted': deleted
    }

def print_critical_report(comparison_data):
    """Display an executive terminal summary of critical security findings."""
    cat = categorize_findings(comparison_data)
    mod_bin = cat['mod_binaries']
    susp_new = cat['suspicious_new']
    summary = comparison_data.get('summary', {})

    print("\n" + "="*80)
    print("CRITICAL SECURITY FINDINGS REPORT".center(80))
    print("="*80)
    print(f"Analysis Time: {comparison_data.get('analysis_timestamp', 'Unknown')}")
    print(f"Clean Baseline: {comparison_data.get('clean_scan_file', 'Unknown')}")
    print(f"Target Scan:    {comparison_data.get('target_scan_file', 'Unknown')}")
    print("-"*80)
    print(f"Total Files Analyzed (Clean / Target): {comparison_data.get('clean_total_files', 0):,} / {comparison_data.get('target_total_files', 0):,}")
    print(f"Differences: Modified={summary.get('modified_files_count', 0):,} | New={summary.get('new_files_count', 0):,} | Deleted={summary.get('deleted_files_count', 0):,}")
    print("-"*80)
    print("EXECUTIVE SECURITY SUMMARY")
    print(f"  [CRITICAL] Modified System Binaries: {len(mod_bin)}")
    print(f"  [HIGH]     Suspicious New Files:     {len(susp_new)}")
    print("="*80)

    if susp_new:
        print(f"\n1. SUSPICIOUS NEW FILES ({len(susp_new)} detected):")
        print("   (Executable extensions, drop zones, or hidden scripts)")
        print("-"*80)
        for i, f in enumerate(susp_new[:15], 1):
            print(f"[{i}] {f['normalized_path']}")
            print(f"    Size:     {format_size(f.get('size_bytes'))}")
            print(f"    MD5:      {f.get('md5_hash')}")
            print(f"    Created:  {f.get('modification_datetime')}")
        if len(susp_new) > 15:
            print(f"    ... and {len(susp_new) - 15} more (see CSV report).")

    if mod_bin:
        print(f"\n2. MODIFIED SYSTEM BINARIES ({len(mod_bin)} detected):")
        print("   (Hash mismatch in system executable directories - potential tampering!)")
        print("-"*80)
        for i, f in enumerate(mod_bin[:15], 1):
            print(f"[{i}] {f['normalized_path']}")
            print(f"    Clean MD5:  {f.get('clean_md5')}")
            print(f"    Target MD5: {f.get('target_md5')}")
        if len(mod_bin) > 15:
            print(f"    ... and {len(mod_bin) - 15} more (see CSV report).")

    if not susp_new and not mod_bin:
        print("\n[+] Clean check! No modified binaries or suspicious new files detected.")
    print("="*80 + "\n")

def generate_csv_report(comparison_data, output_csv):
    """Exports structured findings into a CSV report with severity tags."""
    cat = categorize_findings(comparison_data)
    rows = []

    # 1. Suspicious New Files
    for f in cat['suspicious_new']:
        sev = 'CRITICAL' if is_system_binary(f['normalized_path']) else 'HIGH'
        rows.append({
            'Category': 'Suspicious New File',
            'Suggested Severity': sev,
            'Path': f['normalized_path'],
            'Status': 'New',
            'Size': f.get('size_bytes', 0),
            'Clean MD5': 'N/A',
            'Target MD5': f.get('md5_hash', 'Unknown'),
            'Modification Time': f.get('modification_datetime', 'Unknown')
        })

    # 2. Modified System Binaries
    for f in cat['mod_binaries']:
        rows.append({
            'Category': 'Modified System Binary',
            'Suggested Severity': 'CRITICAL',
            'Path': f['normalized_path'],
            'Status': 'Modified',
            'Size': f.get('target_size', 0),
            'Clean MD5': f.get('clean_md5', 'Unknown'),
            'Target MD5': f.get('target_md5', 'Unknown'),
            'Modification Time': f.get('target_modification_time', 'Unknown')
        })

    # 3. Other Modified Files
    for f in cat['other_modified']:
        rows.append({
            'Category': 'Modified File',
            'Suggested Severity': 'MEDIUM',
            'Path': f['normalized_path'],
            'Status': 'Modified',
            'Size': f.get('target_size', 0),
            'Clean MD5': f.get('clean_md5', 'Unknown'),
            'Target MD5': f.get('target_md5', 'Unknown'),
            'Modification Time': f.get('target_modification_time', 'Unknown')
        })

    # 4. Other New Files
    for f in cat['other_new']:
        rows.append({
            'Category': 'New File',
            'Suggested Severity': 'LOW',
            'Path': f['normalized_path'],
            'Status': 'New',
            'Size': f.get('size_bytes', 0),
            'Clean MD5': 'N/A',
            'Target MD5': f.get('md5_hash', 'Unknown'),
            'Modification Time': f.get('modification_datetime', 'Unknown')
        })

    # 5. Deleted Files
    for f in cat['deleted']:
        rows.append({
            'Category': 'Deleted File',
            'Suggested Severity': 'MEDIUM',
            'Path': f['normalized_path'],
            'Status': 'Deleted',
            'Size': f.get('size_bytes', 0),
            'Clean MD5': f.get('md5_hash', 'Unknown'),
            'Target MD5': 'N/A',
            'Modification Time': f.get('modification_datetime', 'Unknown')
        })

    fieldnames = [
        'Category', 'Suggested Severity', 'Path', 'Status',
        'Size', 'Clean MD5', 'Target MD5', 'Modification Time'
    ]

    os.makedirs(os.path.dirname(os.path.abspath(output_csv)), exist_ok=True)
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Successfully exported {len(rows):,} findings to CSV: {output_csv}")

# ----------------------------------------------------------------------
# 4. Baseline File Discovery
# ----------------------------------------------------------------------

def find_clean_json():
    """Locates clean.json in current directory or clean/ subdirectories."""
    # 1. Exact match in current directory
    if os.path.exists("clean.json"):
        print("[+] Found 'clean.json' in current directory.")
        return "clean.json"

    # 2. Check clean/baseline/clean.json
    clean_baseline = os.path.join("clean", "baseline", "clean.json")
    if os.path.exists(clean_baseline):
        print(f"[+] Found baseline at: {clean_baseline}")
        return clean_baseline

    # 3. Recursive search in clean folder
    if os.path.exists("clean"):
        for root, dirs, files in os.walk("clean"):
            if "clean.json" in files:
                found = os.path.join(root, "clean.json")
                print(f"[+] Found baseline at: {found}")
                return found
            # First JSON inside baseline subfolder
            if "baseline" in root.lower():
                jsons = [f for f in files if f.endswith('.json')]
                if jsons:
                    found = os.path.join(root, jsons[0])
                    print(f"[*] Using baseline: {found}")
                    return found

    return None

# ----------------------------------------------------------------------
# 5. Workflow Procedures
# ----------------------------------------------------------------------

def workflow_baseline_scan(scan_path=None):
    """Creates a fresh clean.json baseline scan."""
    print("\n" + "="*70)
    print("STEP 1: CREATING BASELINE SCAN (CLEAN STATE)".center(70))
    print("="*70)
    out_file = scan_filesystem(start_path=scan_path)
    if out_file and os.path.exists(out_file):
        shutil.copy2(out_file, "clean.json")
        print(f"\n[+] Baseline snapshot created and saved as 'clean.json' in current directory.")
        return "clean.json"
    else:
        print("\n[-] Error: Failed to generate baseline scan.")
        return None

def workflow_target_scan_and_compare(baseline_path=None, scan_path=None):
    """Runs target scan, compares against clean.json, and outputs reports."""
    print("\n" + "="*70)
    print("STEP 2: SCANNING TARGET SYSTEM & COMPARING WITH BASELINE".center(70))
    print("="*70)

    if not baseline_path:
        baseline_path = find_clean_json()

    if not baseline_path:
        print("[-] Error: Baseline scan 'clean.json' not found!")
        print("    Please run Option 1 first to create clean.json, or supply a baseline path.")
        return

    print(f"[*] Active Baseline: {baseline_path}")
    target_scan_file = scan_filesystem(start_path=scan_path, verbose=True)
    if not target_scan_file or not os.path.exists(target_scan_file):
        print("[-] Target scan failed.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outcome_dir = os.path.join(os.getcwd(), f"scan_results_{timestamp}")
    os.makedirs(outcome_dir, exist_ok=True)

    target_json = os.path.join(outcome_dir, "target.json")
    compare_json = os.path.join(outcome_dir, "compare.json")
    csv_report = os.path.join(outcome_dir, "critical_findings.csv")

    shutil.copy2(target_scan_file, target_json)
    print(f"\n[+] Saved target scan to: {target_json}")

    print(f"[*] Comparing target scan against baseline...")
    comparison = compare_scans(baseline_path, target_json, output_file=compare_json)
    if not comparison:
        print("[-] Comparison failed.")
        return

    print(f"[+] Diff comparison saved to: {compare_json}")
    generate_csv_report(comparison, csv_report)
    print_critical_report(comparison)

    print(f"[*] All results stored in folder: {outcome_dir}")

def workflow_compare_existing(clean_path, target_path, output_csv=None, output_json=None):
    """Directly compares two existing scan JSON files."""
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

    if not output_csv:
        output_csv = output_json.replace(".json", "_findings.csv")

    generate_csv_report(comparison, output_csv)
    print_critical_report(comparison)

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
            print(f"  - {item.get('full_path')} | {format_size(item.get('size_bytes'))} | {item.get('md5_hash')}")
    elif isinstance(data, dict) and 'summary' in data:
        summary = data['summary']
        print("Type: Comparison Results")
        print(f"Analysis Time: {data.get('analysis_timestamp')}")
        print(f"Modified Files: {summary.get('modified_files_count', 0):,}")
        print(f"New Files:      {summary.get('new_files_count', 0):,}")
        print(f"Deleted Files:  {summary.get('deleted_files_count', 0):,}")
        print_critical_report(data)
    else:
        print("Unknown JSON format.")

# ----------------------------------------------------------------------
# 6. Interactive Menu & CLI Dispatcher
# ----------------------------------------------------------------------

def interactive_menu():
    while True:
        print("\n" + "="*75)
        print("UNIFIED FILESYSTEM SCANNER AND INTEGRITY CHECKER".center(75))
        print("="*75)
        print("  1. Create Clean JSON file (Baseline Scan)")
        print("  2. Scan Target, Compare with Baseline, and Generate Reports")
        print("  3. Scan Baseline & Target Sequentially (Full Benchmark)")
        print("  4. Compare Two Existing JSON Files")
        print("  5. Inspect / View a Scan or Comparison JSON File")
        print("  6. Exit")
        print("="*75)

        try:
            choice = input("\nEnter your choice (1-6): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting... Goodbye!")
            break

        if choice == '1':
            custom = input("Enter path to scan (or press Enter for default root): ").strip()
            workflow_baseline_scan(custom if custom else None)
        elif choice == '2':
            custom = input("Enter path to scan (or press Enter for default root): ").strip()
            workflow_target_scan_and_compare(scan_path=custom if custom else None)
        elif choice == '3':
            clean_file = workflow_baseline_scan()
            if clean_file:
                time.sleep(1)
                workflow_target_scan_and_compare(baseline_path=clean_file)
        elif choice == '4':
            clean_p = input("Enter path to clean baseline JSON: ").strip()
            target_p = input("Enter path to target JSON: ").strip()
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
        elif choice in ('6', 'exit', 'quit'):
            print("\nExiting... Goodbye!")
            break
        else:
            print("\n[-] Invalid option. Please select 1 through 6.")

def main():
    parser = argparse.ArgumentParser(
        description="Unified Filesystem Scanner and Integrity Checker"
    )
    parser.add_argument("--baseline", action="store_true", help="Create baseline scan (clean.json)")
    parser.add_argument("--target", action="store_true", help="Scan target and compare against clean.json")
    parser.add_argument("--compare", nargs=2, metavar=('CLEAN_JSON', 'TARGET_JSON'), help="Compare two scan JSON files")
    parser.add_argument("--view", metavar="JSON_FILE", help="View summary of a scan or comparison JSON")
    parser.add_argument("--path", help="Custom path to scan (defaults to C:\\ or /)")
    parser.add_argument("--output-csv", help="Custom path for output CSV report")
    parser.add_argument("--output-json", help="Custom path for output comparison JSON")

    args = parser.parse_args()

    # CLI Dispatch
    if args.baseline:
        workflow_baseline_scan(scan_path=args.path)
    elif args.target:
        workflow_target_scan_and_compare(scan_path=args.path)
    elif args.compare:
        workflow_compare_existing(
            args.compare[0],
            args.compare[1],
            output_csv=args.output_csv,
            output_json=args.output_json
        )
    elif args.view:
        view_json_summary(args.view)
    else:
        interactive_menu()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
