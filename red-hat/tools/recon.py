"""
RED HAT Security Lab - Recon Engine
Web-focused reconnaissance: DNS, WHOIS, ports, headers, paths, subdomains.
For authorized penetration testing only.
"""

import socket
import threading
import os
from datetime import datetime

import requests
import dns.resolver
import whois
from colorama import Fore, Style, init

init(autoreset=True)


# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN LISTS — no external files needed
# ─────────────────────────────────────────────────────────────────────────────
SUBDOMAINS = [
    'www', 'mail', 'ftp', 'dev', 'api', 'staging', 'test', 'beta',
    'admin', 'portal', 'vpn', 'remote', 'shop', 'blog', 'forum',
    'support', 'help', 'docs', 'cdn', 'static', 'media', 'images',
    'app', 'mobile', 'secure', 'login', 'auth', 'dashboard', 'panel',
    'cpanel', 'webmail', 'smtp', 'pop', 'imap', 'mx', 'ns1', 'ns2',
    'git', 'svn', 'jira', 'wiki', 'intranet', 'internal', 'corp',
    'old', 'new', 'backup', 'bak', 'demo', 'sandbox', 'preprod',
    'prod', 'store', 'checkout', 'payment', 'status', 'monitor',
    'metrics', 'analytics', 'search', 'proxy', 'video', 'stream',
    'cloud', 'data', 'db', 'smtp2', 'mx1', 'mx2', 'ns3', 'ns4',
]

COMMON_PATHS = [
    # Admin panels
    '/admin', '/administrator', '/admin.php', '/admin/login',
    '/dashboard', '/panel', '/controlpanel', '/control',
    '/cpanel', '/console', '/manager',
    # WordPress
    '/wp-admin', '/wp-login.php', '/wp-content/uploads',
    '/wp-content/plugins', '/wp-content/themes',
    '/xmlrpc.php', '/wp-json/wp/v2/users',
    # Auth
    '/login', '/login.php', '/signin', '/user/login', '/account/login',
    '/register', '/signup',
    # File upload
    '/upload', '/uploads', '/file-upload', '/files', '/fileupload',
    '/media', '/attachments',
    # Sensitive files
    '/backup', '/backup.zip', '/backup.tar.gz', '/db_backup.sql',
    '/config', '/config.php', '/.env', '/env', '/configuration.php',
    '/phpinfo.php', '/info.php', '/test.php',
    '/robots.txt', '/sitemap.xml', '/.htaccess', '/.htpasswd',
    '/.git', '/.git/config', '/.svn', '/.DS_Store',
    '/readme.txt', '/README.md', '/CHANGELOG', '/VERSION',
    # Server status
    '/server-status', '/server-info',
    # Database tools
    '/phpmyadmin', '/pma', '/adminer.php',
    # APIs
    '/api', '/api/v1', '/api/v2', '/graphql', '/swagger',
    '/swagger-ui.html', '/api-docs',
    # CGI
    '/cgi-bin', '/cgi-bin/admin.cgi',
    # Known webshell names (detect if already compromised)
    '/shell.php', '/cmd.php', '/webshell.php', '/c99.php', '/r57.php',
    '/debug', '/trace',
]

WEB_PORTS = [
    (21,    'FTP'),
    (22,    'SSH'),
    (23,    'Telnet'),
    (25,    'SMTP'),
    (53,    'DNS'),
    (80,    'HTTP'),
    (443,   'HTTPS'),
    (445,   'SMB'),
    (1433,  'MSSQL'),
    (3000,  'Node/Dev'),
    (3306,  'MySQL'),
    (4444,  'Shell/Metasploit'),
    (5000,  'Flask/Dev'),
    (5432,  'PostgreSQL'),
    (5900,  'VNC'),
    (6379,  'Redis'),
    (8000,  'HTTP-Dev'),
    (8080,  'HTTP-Alt'),
    (8443,  'HTTPS-Alt'),
    (8888,  'HTTP-Dev'),
    (9200,  'Elasticsearch'),
    (27017, 'MongoDB'),
]

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy',
]

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}


# ─────────────────────────────────────────────────────────────────────────────
# HOST / CMS DETECTION
# ─────────────────────────────────────────────────────────────────────────────
def detect_host_type(response):
    content  = response.text.lower()
    headers  = {k.lower(): v.lower() for k, v in response.headers.items()}
    server   = headers.get('server', '')
    powered  = headers.get('x-powered-by', '')
    gen      = headers.get('x-generator', '')

    detections = []

    if 'wp-content' in content or 'wp-includes' in content or 'wordpress' in content:
        detections.append('WordPress')
    if 'wix.com' in content or 'wixsite' in content or 'wix-bolt' in content:
        detections.append('Wix  [Managed — Limited Shell Access]')
    if 'squarespace' in content:
        detections.append('Squarespace  [Managed — No Shell Access]')
    if 'shopify' in content or 'myshopify' in content:
        detections.append('Shopify  [Managed — No Shell Access]')
    if 'drupal' in content or 'drupal' in gen:
        detections.append('Drupal')
    if 'joomla' in content:
        detections.append('Joomla')
    if 'laravel' in powered or 'laravel_session' in content:
        detections.append('Laravel (PHP)')
    if 'django' in content or 'csrfmiddlewaretoken' in content:
        detections.append('Django (Python)')
    if 'nginx' in server:
        detections.append(f'Nginx  ({server})')
    if 'apache' in server:
        detections.append(f'Apache  ({server})')
    if 'iis' in server or 'microsoft' in server:
        detections.append(f'IIS / Windows  ({server})')
    if 'php' in powered:
        detections.append(f'PHP  ({powered})')

    if not detections:
        detections.append('Unknown / Static Site  [No Shell Access Likely]')

    return detections


# ─────────────────────────────────────────────────────────────────────────────
# SCAN FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
def dns_lookup(target):
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 3
    resolver.lifetime = 3

    for rtype in ['A', 'MX', 'TXT', 'NS', 'CNAME']:
        try:
            answers = resolver.resolve(target, rtype)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            results[rtype] = []

    return results


def whois_lookup(target):
    try:
        w = whois.whois(target)
        return {
            'Registrar':        str(getattr(w, 'registrar',       'N/A')),
            'Creation Date':    str(getattr(w, 'creation_date',   'N/A')),
            'Expiration Date':  str(getattr(w, 'expiration_date', 'N/A')),
            'Country':          str(getattr(w, 'country',         'N/A')),
            'Org':              str(getattr(w, 'org',             'N/A')),
        }
    except Exception as e:
        return {'Error': str(e)}


def port_scan(target_ip, timeout=1):
    open_ports = []
    lock = threading.Lock()

    def scan_port(port, service):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((target_ip, port)) == 0:
                banner = ''
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    raw = sock.recv(1024).decode(errors='ignore')
                    banner = raw.split('\n')[0].strip()
                except Exception:
                    pass
                with lock:
                    open_ports.append({'port': port, 'service': service, 'banner': banner})
            sock.close()
        except Exception:
            pass

    threads = [threading.Thread(target=scan_port, args=(p, s)) for p, s in WEB_PORTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return sorted(open_ports, key=lambda x: x['port'])


def http_analysis(url):
    try:
        resp = requests.get(url, timeout=6, allow_redirects=True, headers=HEADERS)
        present_h, missing_h = [], []
        resp_lower_keys = {k.lower() for k in resp.headers}

        for h in SECURITY_HEADERS:
            if h.lower() in resp_lower_keys:
                present_h.append(h)
            else:
                missing_h.append(h)

        return {
            'status_code':     resp.status_code,
            'server':          resp.headers.get('Server',       'Not disclosed'),
            'x_powered_by':    resp.headers.get('X-Powered-By', 'Not disclosed'),
            'present_headers': present_h,
            'missing_headers': missing_h,
            'host_type':       detect_host_type(resp),
        }
    except Exception as e:
        return {'error': str(e)}


def path_probe(base_url, output_mode, report_lines):
    found = []
    lock  = threading.Lock()

    def probe(path):
        try:
            resp = requests.get(
                base_url.rstrip('/') + path,
                timeout=3,
                allow_redirects=False,
                headers=HEADERS
            )
            if resp.status_code in (200, 301, 302, 403, 500):
                color = Fore.GREEN if resp.status_code == 200 else Fore.YELLOW
                print(f"    {color}[{resp.status_code}]{Style.RESET_ALL} {path}")
                with lock:
                    found.append({'path': path, 'status': resp.status_code})
                    log_output(f"    [{resp.status_code}] {path}", output_mode, report_lines)
        except Exception:
            pass

    batch_size = 20
    paths = list(COMMON_PATHS)
    for i in range(0, len(paths), batch_size):
        batch = paths[i:i + batch_size]
        threads = [threading.Thread(target=probe, args=(p,)) for p in batch]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    return found


def subdomain_enum(domain, output_mode, report_lines):
    found    = []
    lock     = threading.Lock()
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 2
    resolver.lifetime = 2

    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, 'A')
            ip = str(answers[0])
            print(f"    {Fore.GREEN}[FOUND]{Style.RESET_ALL} {fqdn}  →  {ip}")
            with lock:
                found.append({'subdomain': fqdn, 'ip': ip})
                log_output(f"    [FOUND] {fqdn} -> {ip}", output_mode, report_lines)
        except Exception:
            pass

    batch_size = 30
    subs = list(SUBDOMAINS)
    for i in range(0, len(subs), batch_size):
        batch = subs[i:i + batch_size]
        threads = [threading.Thread(target=check_sub, args=(s,)) for s in batch]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    return found


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT HELPER
# ─────────────────────────────────────────────────────────────────────────────
def log_output(line, output_mode, report_lines):
    if output_mode in ('save', 'both'):
        report_lines.append(line)


def save_report(target, report_lines):
    os.makedirs('reports', exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename  = f"reports/recon_{target}_{timestamp}.txt"
    with open(filename, 'w') as f:
        f.write('\n'.join(report_lines))
    print(f"\n  {Fore.GREEN}[+] Report saved: {filename}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RECON RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def run_recon(output_mode):
    report_lines = []

    print(f"\n{Fore.BLUE}  ╔══════════════════════════════════════════════════════╗")
    print(f"  ║                  RECON ENGINE                        ║")
    print(f"  ╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

    target = input(f"  {Fore.WHITE}Enter target domain or IP: {Style.RESET_ALL}").strip()
    if not target:
        print(f"  {Fore.RED}[!] No target provided.{Style.RESET_ALL}")
        return

    target_clean = target.replace('https://', '').replace('http://', '').split('/')[0]
    base_url     = f"http://{target_clean}"

    log_output("RED HAT RECON REPORT", output_mode, report_lines)
    log_output(f"Target : {target_clean}", output_mode, report_lines)
    log_output(f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", output_mode, report_lines)
    log_output('=' * 60, output_mode, report_lines)

    # ── IP Resolution ──────────────────────────────────────────────────────
    print(f"\n  {Fore.CYAN}[*] Resolving IP...{Style.RESET_ALL}")
    try:
        target_ip = socket.gethostbyname(target_clean)
        print(f"      {Fore.GREEN}{target_ip}{Style.RESET_ALL}")
        log_output(f"IP: {target_ip}", output_mode, report_lines)
    except Exception as e:
        print(f"      {Fore.RED}[!] Could not resolve: {e}{Style.RESET_ALL}")
        return

    # ── DNS Records ────────────────────────────────────────────────────────
    print(f"\n  {Fore.CYAN}[*] DNS Records...{Style.RESET_ALL}")
    log_output("\n[DNS RECORDS]", output_mode, report_lines)
    dns_data = dns_lookup(target_clean)
    found_any = False
    for rtype, records in dns_data.items():
        for r in records:
            print(f"      {Fore.YELLOW}{rtype:<8}{Style.RESET_ALL}{Fore.WHITE}{r}{Style.RESET_ALL}")
            log_output(f"  {rtype}: {r}", output_mode, report_lines)
            found_any = True
    if not found_any:
        print(f"      {Fore.YELLOW}No records returned.{Style.RESET_ALL}")

    # ── WHOIS ──────────────────────────────────────────────────────────────
    print(f"\n  {Fore.CYAN}[*] WHOIS Lookup...{Style.RESET_ALL}")
    log_output("\n[WHOIS]", output_mode, report_lines)
    whois_data = whois_lookup(target_clean)
    for k, v in whois_data.items():
        if v and v not in ('N/A', 'None'):
            print(f"      {Fore.YELLOW}{k:<18}{Style.RESET_ALL}{Fore.WHITE}{str(v)[:60]}{Style.RESET_ALL}")
            log_output(f"  {k}: {v}", output_mode, report_lines)

    # ── Port Scan ──────────────────────────────────────────────────────────
    print(f"\n  {Fore.CYAN}[*] Port Scan ({len(WEB_PORTS)} ports)...{Style.RESET_ALL}")
    log_output("\n[PORT SCAN]", output_mode, report_lines)
    open_ports = port_scan(target_ip)
    if open_ports:
        for p in open_ports:
            banner_str = f"  {p['banner'][:45]}" if p['banner'] else ''
            print(
                f"      {Fore.GREEN}OPEN{Style.RESET_ALL}  "
                f"{Fore.WHITE}{p['port']:<7}{Style.RESET_ALL}"
                f"{Fore.YELLOW}{p['service']:<18}{Style.RESET_ALL}"
                f"{Fore.WHITE}{banner_str}{Style.RESET_ALL}"
            )
            log_output(f"  OPEN {p['port']} {p['service']} {p['banner'][:45]}", output_mode, report_lines)
    else:
        print(f"      {Fore.YELLOW}No open ports detected.{Style.RESET_ALL}")

    # ── HTTP Analysis ──────────────────────────────────────────────────────
    print(f"\n  {Fore.CYAN}[*] HTTP Analysis...{Style.RESET_ALL}")
    log_output("\n[HTTP ANALYSIS]", output_mode, report_lines)
    http_data = http_analysis(base_url)

    host_types = ['Unknown']
    if 'error' not in http_data:
        print(f"      {Fore.YELLOW}Status Code : {Style.RESET_ALL}{Fore.WHITE}{http_data['status_code']}{Style.RESET_ALL}")
        print(f"      {Fore.YELLOW}Server      : {Style.RESET_ALL}{Fore.WHITE}{http_data['server']}{Style.RESET_ALL}")
        print(f"      {Fore.YELLOW}Powered By  : {Style.RESET_ALL}{Fore.WHITE}{http_data['x_powered_by']}{Style.RESET_ALL}")
        log_output(f"  Status: {http_data['status_code']}", output_mode, report_lines)
        log_output(f"  Server: {http_data['server']}", output_mode, report_lines)

        host_types = http_data['host_type']
        print(f"\n      {Fore.CYAN}Host / CMS Detection:{Style.RESET_ALL}")
        for ht in host_types:
            is_managed = any(x in ht for x in ('Managed', 'Static', 'No Shell'))
            color = Fore.RED if is_managed else Fore.GREEN
            print(f"        {color}→  {ht}{Style.RESET_ALL}")
            log_output(f"  Host Type: {ht}", output_mode, report_lines)

        print(f"\n      {Fore.GREEN}Security Headers Present:{Style.RESET_ALL}")
        for h in http_data['present_headers']:
            print(f"        {Fore.GREEN}[✓]{Style.RESET_ALL}  {h}")

        print(f"\n      {Fore.RED}Security Headers Missing:{Style.RESET_ALL}")
        for h in http_data['missing_headers']:
            print(f"        {Fore.RED}[✗]{Style.RESET_ALL}  {h}")
            log_output(f"  MISSING HEADER: {h}", output_mode, report_lines)
    else:
        print(f"      {Fore.RED}[!] HTTP error: {http_data['error']}{Style.RESET_ALL}")

    # ── Subdomain Enumeration ──────────────────────────────────────────────
    print(f"\n  {Fore.CYAN}[*] Subdomain Enumeration ({len(SUBDOMAINS)} targets)...{Style.RESET_ALL}")
    log_output("\n[SUBDOMAINS]", output_mode, report_lines)
    found_subs = subdomain_enum(target_clean, output_mode, report_lines)
    if not found_subs:
        print(f"      {Fore.YELLOW}No subdomains discovered.{Style.RESET_ALL}")

    # ── Path Probing ───────────────────────────────────────────────────────
    print(f"\n  {Fore.CYAN}[*] Path Probing ({len(COMMON_PATHS)} paths)...{Style.RESET_ALL}")
    log_output("\n[PATH PROBE]", output_mode, report_lines)
    found_paths = path_probe(base_url, output_mode, report_lines)
    if not found_paths:
        print(f"      {Fore.YELLOW}No interesting paths discovered.{Style.RESET_ALL}")

    # ── Payload Recommendation ─────────────────────────────────────────────
    is_managed = any(
        any(x in ht for x in ('Managed', 'Static', 'No Shell'))
        for ht in host_types
    )
    is_wordpress = any('WordPress' in ht for ht in host_types)

    if is_managed:
        payload_rec = f"{Fore.RED}LIMITED — Managed host. XSS / SQLi only.{Style.RESET_ALL}"
    elif is_wordpress:
        payload_rec = f"{Fore.GREEN}PHP Web Shell, PHP Reverse Shell, Plugin upload vectors.{Style.RESET_ALL}"
    elif open_ports:
        payload_rec = f"{Fore.GREEN}PHP Shell, Bash/Python Reverse Shell.{Style.RESET_ALL}"
    else:
        payload_rec = f"{Fore.YELLOW}No confirmed vectors — manual investigation suggested.{Style.RESET_ALL}"

    log_output(f"\nPAYLOAD RECOMMENDATION: {payload_rec}", output_mode, report_lines)

    # ── Summary Box ────────────────────────────────────────────────────────
    print(f"""
  {Fore.BLUE}╔══════════════════════════════════════════════════════╗
  ║                    RECON SUMMARY                     ║
  ╠══════════════════════════════════════════════════════╣{Style.RESET_ALL}""")
    print(f"  {Fore.CYAN}Target      :{Style.RESET_ALL}  {Fore.WHITE}{target_clean}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}IP          :{Style.RESET_ALL}  {Fore.WHITE}{target_ip}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Open Ports  :{Style.RESET_ALL}  {Fore.WHITE}{len(open_ports)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Subdomains  :{Style.RESET_ALL}  {Fore.WHITE}{len(found_subs)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Found Paths :{Style.RESET_ALL}  {Fore.WHITE}{len(found_paths)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Payload Rec :{Style.RESET_ALL}  {payload_rec}")
    print(f"  {Fore.BLUE}╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    if output_mode in ('save', 'both'):
        save_report(target_clean, report_lines)

    input(f"\n  {Fore.WHITE}Press Enter to return to menu...{Style.RESET_ALL}")
