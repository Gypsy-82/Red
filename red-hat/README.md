<div align="center">

```
██████╗ ███████╗██████╗     ██╗  ██╗ █████╗ ████████╗
██╔══██╗██╔════╝██╔══██╗    ██║  ██║██╔══██╗╚══██╔══╝
██████╔╝█████╗  ██║  ██║    ███████║███████║   ██║
██╔══██╗██╔══╝  ██║  ██║    ██╔══██║██╔══██║   ██║
██║  ██║███████╗██████╔╝    ██║  ██║██║  ██║   ██║
╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
```

**Web Penetration Testing Toolkit**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Tested](https://img.shields.io/badge/Tested%20On-Kali%20%7C%20Ubuntu%20%7C%20Arch-red?style=flat-square)

*Self-contained. No APIs. No wordlists. No payload folders. Everything built in.*

</div>

---

## Legal Notice

> This toolkit is intended **solely** for use on systems you own or have **explicit written authorization** to test.
> Unauthorized use against systems you do not own or have permission to access is **illegal** under the Computer Fraud and Abuse Act (CFAA) and equivalent international law.
> The author assumes **zero liability** for misuse. Use responsibly. Stay authorized.

---

## What Is This?

RED HAT is a modular, terminal-based web penetration testing toolkit built for IT security professionals and authorized engagements. It covers two phases of a web pentest in a single, self-contained Python suite:

| Phase | Tool | Purpose |
|-------|------|---------|
| **Recon** | `recon.py` | Fingerprint, enumerate, and map the target |
| **Exploitation** | `payload.py` | Generate payloads, deliver them, and manage the session |

Both tools launch from a single master launcher with a live environment check, dependency auto-installer, output mode selector, and secure session shredder on exit.

---

## Features

### Master Launcher
- **Venv enforcement** — hard stops if not running inside a virtual environment, with setup instructions displayed
- **Auto-installer** — detects missing packages and installs them on first run, zero manual setup
- **Output mode** — choose terminal only, save to `/reports/`, or both before the session starts
- **Secure exit** — optional 3-pass random overwrite shred of all session data on exit (single file, batch, or all)

---

### Tool 1 — Recon Engine

Full target reconnaissance from a single domain or IP input.

```
Enter target domain or IP: example.com

[*] Resolving IP...          93.184.216.34
[*] DNS Records...           A / MX / TXT / NS / CNAME
[*] WHOIS Lookup...          Registrar / Dates / Org / Country
[*] Port Scan...             21 FTP | 22 SSH | 80 HTTP | 443 HTTPS | ...
[*] HTTP Analysis...         Server / CMS / Security Headers
[*] Subdomain Enumeration... www | mail | dev | api | staging | ...
[*] Path Probing...          /admin | /wp-login | /uploads | /.env | ...
```

**Capabilities:**

- DNS enumeration — A, MX, TXT, NS, CNAME records
- WHOIS lookup — registrar, dates, org, country
- Multi-threaded port scan — 20 web-focused ports with banner grabbing
- HTTP security header audit — flags missing HSTS, CSP, X-Frame-Options, and more
- Host/CMS fingerprinting — WordPress, Wix, Squarespace, Shopify, Drupal, Joomla, Laravel, Django, Apache, Nginx, IIS, PHP
- Built-in subdomain list — ~55 common names, threaded DNS resolution
- Built-in path list — ~45 common sensitive paths probed with status code reporting
- Payload recommendation — based on detected host type, tells you exactly what payloads are viable

---

### Tool 2 — Payload Generator + C2 Console

Generate, deliver, and manage payloads interactively.

**Payload Types:**

| # | Payload | Delivery | Listener |
|---|---------|----------|----------|
| 1 | PHP Web Shell | Upload attempt to target endpoint | Not required |
| 2 | PHP Reverse Shell | Upload attempt + optional listener | Yes |
| 3 | Bash Reverse Shell | Manual / display | Yes |
| 4 | Python Reverse Shell | Manual / display | Yes |
| 5 | XSS Payloads | Display (8 vectors with descriptions) | No |
| 6 | SQL Injection Templates | Display (12 templates with descriptions) | No |

**Live C2 Dashboard** (activates on shell connect):

```
╔══════════════════════════════════════════════════════════════╗
║                    RED HAT C2 CONSOLE                        ║
╠══════════════════════════════════════════════════════════════╣
║  LHOST: 192.168.1.10        LPORT: 4444                      ║
║  TARGET: 192.168.1.50       STATUS: CONNECTED                ║
║  SESSION TIME: 00:04:32                                      ║
╠══════════════════════════════════════════════════════════════╣
║  ATTEMPTS: 7    SUCCESS: 1    FAILED: 6                      ║
╠══════════════════════════════════════════════════════════════╣
║  SHELL:     /bin/bash (Linux)                                ║
║  OS:        Linux ubuntu 6.17.0  ARCH: x86_64               ║
║  PRIVILEGE: www-data                                         ║
╠══════════════════════════════════════════════════════════════╣
║  LOGGED IN USERS:                                            ║
║    root    pts/0   192.168.1.1   Mar 12 09:14                ║
╠══════════════════════════════════════════════════════════════╣
║  ESCALATION HINTS:                                           ║
║  → Check sudo -l for allowed commands                        ║
║  → find / -perm -u=s -type f 2>/dev/null                     ║
║  → Upgrade shell: python3 -c 'import pty; pty.spawn(...)'    ║
╠══════════════════════════════════════════════════════════════╣
║  LAST CMD:  whoami                                           ║
║  RESPONSE:  www-data                                         ║
╠══════════════════════════════════════════════════════════════╣
║  [C2 SHELL] >> _                                             ║
╚══════════════════════════════════════════════════════════════╝
```

- Auto shell-type detection — bash, sh, zsh, PowerShell, cmd.exe
- Auto OS, arch, and privilege enumeration on connect
- Logged-in user monitoring — background thread alerts you if a new user logs in during your session
- Context-aware escalation hints — changes based on detected shell type and privilege level
- Session logging — full command/response log saved to `/reports/` if save mode is active

---

## Host Compatibility Matrix

RED HAT automatically detects the target host type and adjusts payload recommendations accordingly.

| Target Type | Shell Viable | Recommended Payload |
|-------------|-------------|---------------------|
| Apache / Nginx (VPS) | Yes | PHP Web Shell, PHP/Bash Reverse Shell |
| WordPress | Yes | PHP Shell via plugin/theme upload |
| Shared Hosting (cPanel) | Limited | PHP only, jailed env |
| IIS / Windows Server | Yes | ASPX shell, PowerShell reverse |
| Wix / Squarespace | No | XSS / SQLi only |
| Static Sites | No | No server-side execution |

---

## Setup

```bash
# Clone the repo
git clone https://github.com/yourusername/red-hat.git
cd red-hat

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Launch — dependencies install automatically on first run
python3 launcher.py
```

**Dependencies (auto-installed):**

| Package | Purpose |
|---------|---------|
| `requests` | HTTP probing, path discovery, payload delivery |
| `dnspython` | DNS record resolution, subdomain enumeration |
| `colorama` | Cross-platform terminal color output |
| `python-whois` | WHOIS lookups |

---

## Workflow

```
                    ┌─────────────────────┐
                    │   python3 launcher  │
                    │   .py               │
                    └────────┬────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
     ┌────────▼────────┐          ┌─────────▼────────┐
     │   [1] RECON     │          │  [2] PAYLOAD      │
     │                 │          │                   │
     │  Enter target   │          │  Select type      │
     │  Full scan      │    ┌────►│  LHOST / LPORT    │
     │  Report output  │    │     │  Generate payload │
     │                 │    │     │  Attempt delivery │
     │  "Try PHP Shell │────┘     │  C2 listener      │
     │   on /uploads"  │          │  Live dashboard   │
     └─────────────────┘          └───────────────────┘
```

---

## Tested Environments

| OS | Version | Status |
|----|---------|--------|
| Ubuntu | 22.04, 24.04 | Tested |
| Kali Linux | 2023.x, 2024.x | Compatible |
| Arch Linux | Rolling | Compatible |
| Parrot OS | 6.x | Compatible |

---

## Project Structure

```
red-hat/
├── launcher.py          # Master menu, venv guard, dependency installer, exit shredder
├── tools/
│   ├── recon.py         # Recon engine — all enumeration and fingerprinting
│   └── payload.py       # Payload generator + C2 dashboard + listener
├── reports/             # Auto-generated session output (gitignored)
├── .gitignore
└── README.md
```

---

## Skills Demonstrated

This project was built to showcase practical, production-quality security tooling:

- **Recon methodology** — DNS, WHOIS, port scanning, banner grabbing, path discovery
- **Payload development** — reverse shells, web shells, XSS, SQLi across multiple languages
- **C2 fundamentals** — socket-based listener, session management, live dashboard
- **OPSEC discipline** — secure shred, no hardcoded credentials, runtime-only sensitive input
- **Cross-distro Python** — works on Kali, Ubuntu, Arch without distro-specific dependencies
- **Secure coding** — no credentials in code, `.gitignore` covering all runtime data, venv enforcement
- **Software architecture** — modular design, master launcher pattern, clean separation of concerns

---

<div align="center">

*Built for authorized penetration testing engagements.*
*If you found this useful, give it a star.*

</div>
