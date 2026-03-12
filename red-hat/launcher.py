#!/usr/bin/env python3
"""
RED HAT Security Lab - Master Launcher
For authorized penetration testing only.
"""

import sys
import os
import subprocess
import importlib
import platform
import shutil

# ─────────────────────────────────────────────────────────────────────────────
# VENV GUARD — Must run before any third-party imports
# ─────────────────────────────────────────────────────────────────────────────
def check_venv():
    if sys.prefix == sys.base_prefix:
        print("""
  ╔══════════════════════════════════════════════════════════════╗
  ║         WARNING: VIRTUAL ENVIRONMENT NOT DETECTED            ║
  ╠══════════════════════════════════════════════════════════════╣
  ║                                                              ║
  ║  This tool requires a virtual environment to run safely.     ║
  ║                                                              ║
  ║  Run the following commands in your project folder:          ║
  ║                                                              ║
  ║    Step 1:  python3 -m venv .venv                            ║
  ║    Step 2:  source .venv/bin/activate                        ║
  ║    Step 3:  python3 launcher.py                              ║
  ║                                                              ║
  ║  Exiting.                                                    ║
  ╚══════════════════════════════════════════════════════════════╝
""")
        sys.exit(1)


check_venv()


# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY INSTALLER
# ─────────────────────────────────────────────────────────────────────────────
REQUIRED_PACKAGES = {
    'requests':  'requests',
    'dns':       'dnspython',
    'colorama':  'colorama',
    'whois':     'python-whois',
}


def install_dependencies():
    missing = []
    for import_name, pip_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append((import_name, pip_name))

    if not missing:
        return

    print(f"\n  [*] First run detected — installing {len(missing)} package(s)...\n")
    for import_name, pip_name in missing:
        print(f"  [+] Installing {pip_name}...", end='', flush=True)
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', pip_name, '-q'],
            capture_output=True
        )
        if result.returncode == 0:
            print(" done")
        else:
            print(f" FAILED")
            print(f"  [!] {result.stderr.decode().strip()}")
            sys.exit(1)
    print("\n  [+] All dependencies ready.\n")


install_dependencies()


# ─────────────────────────────────────────────────────────────────────────────
# Safe to import third-party now
# ─────────────────────────────────────────────────────────────────────────────
from colorama import init, Fore, Style
init(autoreset=True)


# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
def banner():
    print(f"""{Fore.RED}
  ██████╗ ███████╗██████╗     ██╗  ██╗ █████╗ ████████╗
  ██╔══██╗██╔════╝██╔══██╗    ██║  ██║██╔══██╗╚══██╔══╝
  ██████╔╝█████╗  ██║  ██║    ███████║███████║   ██║
  ██╔══██╗██╔══╝  ██║  ██║    ██╔══██║██╔══██║   ██║
  ██║  ██║███████╗██████╔╝    ██║  ██║██║  ██║   ██║
  ╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
{Style.RESET_ALL}  {Fore.WHITE}Web Security Lab  |  Authorized Penetration Testing Only{Style.RESET_ALL}
  {Fore.YELLOW}{'─' * 55}{Style.RESET_ALL}""")


# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT CHECK
# ─────────────────────────────────────────────────────────────────────────────
def env_check():
    python_ok  = sys.version_info >= (3, 9)
    os_info    = f"{platform.system()} {platform.release()}"
    arch       = platform.machine()
    shell      = os.environ.get('SHELL', 'Unknown')
    term_w     = shutil.get_terminal_size().columns

    py_status  = f"{Fore.GREEN}[OK]{Style.RESET_ALL}" if python_ok else f"{Fore.RED}[WARN - Need 3.9+]{Style.RESET_ALL}"

    print(f"\n{Fore.CYAN}  ╔══════════════════════════════════════════════════════╗")
    print(f"  ║                 ENVIRONMENT CHECK                    ║")
    print(f"  ╠══════════════════════════════════════════════════════╣{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}OS:      {Style.RESET_ALL}{Fore.WHITE}{os_info}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Arch:    {Style.RESET_ALL}{Fore.WHITE}{arch}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Python:  {Style.RESET_ALL}{Fore.WHITE}{sys.version.split()[0]}  {py_status}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Venv:    {Style.RESET_ALL}{Fore.GREEN}Active  [OK]{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Colors:  {Style.RESET_ALL}{Fore.GREEN}ANSI Supported  [OK]{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Shell:   {Style.RESET_ALL}{Fore.WHITE}{shell}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Term:    {Style.RESET_ALL}{Fore.WHITE}{term_w} cols{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  ╠══════════════════════════════════════════════════════╣")

    if python_ok:
        print(f"  ║  STATUS: {Fore.GREEN}ALL SYSTEMS GO{Fore.CYAN}                               ║")
    else:
        print(f"  ║  STATUS: {Fore.RED}WARNING — Upgrade Python to 3.9+{Fore.CYAN}             ║")

    print(f"  ╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT MODE SELECTION
# ─────────────────────────────────────────────────────────────────────────────
def set_output_mode():
    print(f"{Fore.CYAN}  ┌─ OUTPUT PREFERENCE ──────────────────────────────────────┐")
    print(f"  │                                                              │")
    print(f"  │  [1]  Terminal only    - nothing written to disk             │")
    print(f"  │  [2]  Save to reports/ - full session log saved              │")
    print(f"  │  [3]  Both             - display AND save                    │")
    print(f"  │                                                              │")
    print(f"  └──────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

    while True:
        choice = input(f"\n  {Fore.WHITE}Select output mode [1-3]: {Style.RESET_ALL}").strip()
        if choice == '1':
            print(f"  {Fore.GREEN}[+] Terminal only — nothing will be saved to disk.{Style.RESET_ALL}")
            return 'terminal'
        elif choice == '2':
            os.makedirs('reports', exist_ok=True)
            print(f"  {Fore.GREEN}[+] Save mode — reports written to /reports/{Style.RESET_ALL}")
            return 'save'
        elif choice == '3':
            os.makedirs('reports', exist_ok=True)
            print(f"  {Fore.GREEN}[+] Both — display and save enabled.{Style.RESET_ALL}")
            return 'both'
        else:
            print(f"  {Fore.RED}[!] Invalid choice. Enter 1, 2, or 3.{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# SECURE SHRED
# ─────────────────────────────────────────────────────────────────────────────
def shred_file(filepath):
    """Overwrite file with random data (3 passes) then delete."""
    try:
        size = os.path.getsize(filepath)
        if size == 0:
            os.remove(filepath)
            return
        with open(filepath, 'r+b') as f:
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(filepath)
    except Exception:
        pass


def exit_handler():
    reports_dir = 'reports'
    has_reports = (
        os.path.isdir(reports_dir) and
        len(os.listdir(reports_dir)) > 0
    )

    if has_reports:
        print(f"""
  {Fore.YELLOW}╔══════════════════════════════════════════════════════╗
  ║                  SESSION CLEANUP                     ║
  ╠══════════════════════════════════════════════════════╣
  ║  Shred session data before exit?                     ║
  ║                                                      ║
  ║  [1]  YES        - Secure delete all reports/logs    ║
  ║  [2]  NO         - Keep files and exit               ║
  ║  [3]  SELECTIVE  - Choose which files to shred       ║
  ╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")
        choice = input(f"  {Fore.WHITE}Select: {Style.RESET_ALL}").strip()

        if choice == '1':
            files = [
                os.path.join(reports_dir, f)
                for f in os.listdir(reports_dir)
            ]
            for filepath in files:
                print(f"  {Fore.RED}[+] Shredding {os.path.basename(filepath)}...{Style.RESET_ALL}")
                shred_file(filepath)
            print(f"  {Fore.GREEN}[+] All session data securely deleted.{Style.RESET_ALL}")

        elif choice == '3':
            files = sorted(os.listdir(reports_dir))
            print()
            for i, fname in enumerate(files, 1):
                print(f"  [{i}] {fname}")
            selections = input(
                f"\n  {Fore.WHITE}File numbers to shred (comma separated): {Style.RESET_ALL}"
            ).strip()
            for s in selections.split(','):
                try:
                    idx = int(s.strip()) - 1
                    filepath = os.path.join(reports_dir, files[idx])
                    print(f"  {Fore.RED}[+] Shredding {files[idx]}...{Style.RESET_ALL}")
                    shred_file(filepath)
                except (ValueError, IndexError):
                    pass
            print(f"  {Fore.GREEN}[+] Selected files securely deleted.{Style.RESET_ALL}")

    print(f"\n  {Fore.RED}[*] Session terminated. Stay legal.{Style.RESET_ALL}\n")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────────────────────────────────────
def main_menu(output_mode):
    while True:
        print(f"""
  {Fore.RED}╔══════════════════════════════════════════════════════╗
  ║                    SELECT TOOL                       ║
  ╠══════════════════════════════════════════════════════╣
  ║  [1]  RECON    - Scan & Fingerprint Target           ║
  ║  [2]  PAYLOAD  - Generate, Deliver & C2 Console      ║
  ║  [0]  EXIT                                           ║
  ╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}""")

        choice = input(f"  {Fore.WHITE}Choose your weapon: {Style.RESET_ALL}").strip()

        if choice == '1':
            from tools.recon import run_recon
            run_recon(output_mode)
        elif choice == '2':
            from tools.payload import run_payload
            run_payload(output_mode)
        elif choice == '0':
            exit_handler()
            break
        else:
            print(f"  {Fore.RED}[!] Invalid choice.{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    banner()
    env_check()
    output_mode = set_output_mode()
    main_menu(output_mode)
