"""
Entry point for LPE Sentinel.
"""

import sys
from pathlib import Path
from typing import Optional

# Allow direct script execution without manual PYTHONPATH modification
PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

try:
    from lpe_sentinel import __version__
except ImportError:
    __version__ = "0.1.0"

try:
    from lpe_sentinel.system_info import collect_system_info, display_system_info
except ImportError:
    from system_info import collect_system_info, display_system_info

try:
    from lpe_sentinel.reporting import build_report_data, save_report_to_file
except ImportError:
    from reporting import build_report_data, save_report_to_file

try:
    from lpe_sentinel.suid_sgid import is_linux_platform, scan_suid_sgid
except ImportError:
    from suid_sgid import is_linux_platform, scan_suid_sgid

try:
    from lpe_sentinel.sensitive_permissions import scan_sensitive_permissions
except ImportError:
    from sensitive_permissions import scan_sensitive_permissions

try:
    from lpe_sentinel.sudo_audit import scan_sudo_config
except ImportError:
    from sudo_audit import scan_sudo_config

try:
    from lpe_sentinel.audit_summary import summarize_findings
except ImportError:
    from audit_summary import summarize_findings

try:
    from lpe_sentinel.summary_formatter import format_audit_summary
except ImportError:
    from summary_formatter import format_audit_summary

import platform


def print_banner() -> None:
    """Display the project banner and startup information."""
    print("=" * 64)
    print(" LPE Sentinel — Linux Privilege Escalation Detection Toolkit ")
    print(f" Version : {__version__}")
    print("=" * 64)
    print("[*] Status : Toolkit is currently under development.")
    print("[*] Scope  : Defensive auditing only — no exploitation payloads.")
    print("=" * 64)


def print_menu() -> None:
    """Display the main menu options."""
    print("\nMain Menu:")
    print("  [1] System Information")
    print("  [2] Security Audit")
    print("  [3] Generate Report")
    print("  [4] Exit")


def print_findings(findings: list) -> None:
    """Display structured findings in a consistent, clean format."""
    print(f"\n[+] Audit completed: {len(findings)} finding(s) discovered.\n")
    for idx, finding in enumerate(findings, 1):
        print("-" * 54)
        print(f" Finding #{idx}: [{finding.finding_id}] ({finding.severity})")
        print(f" Title       : {finding.title}")
        print(f" Resource    : {finding.affected_resource}")
        print(f" Evidence    : {finding.evidence}")
        print(f" Mitigation  : {finding.recommendation}")
    print("-" * 54)


def record_findings(session_findings: list, new_findings: list) -> None:
    """Record newly discovered findings into session state avoiding exact duplicates."""
    existing_keys = {
        (f.finding_id, f.affected_resource, f.evidence) for f in session_findings
    }
    for finding in new_findings:
        key = (finding.finding_id, finding.affected_resource, finding.evidence)
        if key not in existing_keys:
            session_findings.append(finding)
            existing_keys.add(key)


def audit_suid_sgid(session_findings: list) -> bool:
    """Run interactive SUID/SGID file permission scan on explicit directories."""
    print("\n" + "=" * 54)
    print("        SUID / SGID FILE PERMISSION SCAN")
    print("=" * 54)
    print("[*] Scope: SUID/SGID File Permission Inspection.")
    print("[*] Notice: This audit currently checks only SUID/SGID permission bits.")
    print("    It does not inspect the full system automatically.")
    print("=" * 54)

    try:
        user_input = input(
            "\nEnter directory paths to inspect (separated by ';'): "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Audit cancelled. Returning to submenu.")
        return False

    if not user_input:
        print("\n[!] No directories provided. Audit cancelled. Returning to submenu.")
        return False

    raw_paths = [p.strip() for p in user_input.split(";") if p.strip()]
    if not raw_paths:
        print("\n[!] No valid directory paths entered. Returning to submenu.")
        return False

    # Check platform safety before scanning
    if not is_linux_platform():
        print(
            f"\n[!] SUID/SGID scanning is only supported on Linux operating systems.\n"
            f"    Current platform is '{platform.system()}'. No audit performed."
        )
        return False

    print(f"\n[*] Starting SUID/SGID audit across {len(raw_paths)} path(s)...")

    try:
        findings = scan_suid_sgid(raw_paths)
    except Exception as exc:
        print(f"\n[!] An error occurred during the audit: {exc}")
        return False

    if not findings:
        print("\n[*] No SUID/SGID files were detected within the selected accessible paths.")
        print("    (Note: This does not guarantee that the overall system is secure.)")
        return True

    record_findings(session_findings, findings)
    print_findings(findings)
    return True


def audit_sensitive_permissions(session_findings: list) -> bool:
    """Run interactive sensitive file permission check on explicitly supplied file paths."""
    print("\n" + "=" * 54)
    print("       RISKY FILE WRITE PERMISSIONS SCAN")
    print("=" * 54)
    print("[*] Scope: Group- and World-Writable File Permission Check.")
    print("[*] Notice: Checks only explicitly selected file paths.")
    print("    Does not recursively scan directories or enumerate /etc, /home.")
    print("[*] Note: Findings are preliminary permission-risk indicators,")
    print("    not proof that a file is sensitive or exploitable.")
    print("=" * 54)

    try:
        user_input = input(
            "\nEnter file paths to inspect (separated by ';'): "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Audit cancelled. Returning to submenu.")
        return False

    if not user_input:
        print("\n[!] No file paths provided. Audit cancelled. Returning to submenu.")
        return False

    raw_paths = [p.strip() for p in user_input.split(";") if p.strip()]
    if not raw_paths:
        print("\n[!] No valid file paths entered. Returning to submenu.")
        return False

    # Check platform safety before scanning
    if not is_linux_platform():
        print(
            f"\n[!] Sensitive file permission scanning is only supported on Linux operating systems.\n"
            f"    Current platform is '{platform.system()}'. No audit performed."
        )
        return False

    print(f"\n[*] Starting permission audit on {len(raw_paths)} file path(s)...")

    try:
        findings = scan_sensitive_permissions(raw_paths)
    except Exception as exc:
        print(f"\n[!] An error occurred during the audit: {exc}")
        return False

    if not findings:
        print("\n[*] No matching permission issues were detected among the selected accessible files.")
        print("    (Note: This does not guarantee that the overall system is secure.)")
        return True

    record_findings(session_findings, findings)
    print_findings(findings)
    return True


def audit_sudo_configuration(session_findings: list) -> bool:
    """Run interactive sudo configuration audit on explicitly supplied file paths."""
    print("\n" + "=" * 54)
    print("         SUDO CONFIGURATION SECURITY AUDIT")
    print("=" * 54)
    print("[*] Scope: Sudoers Configuration Pattern Inspection.")
    print("[*] Notice: Checks only explicitly selected file paths.")
    print("    Never searches for or assumes default sudoers paths.")
    print("[*] Note: Pattern matches are preliminary indicators, not proof of a vulnerability.")
    print("    Sudoers aliases and syntax can affect interpretation.")
    print("=" * 54)

    try:
        user_input = input(
            "\nEnter sudo configuration file paths to inspect (separated by ';'): "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Audit cancelled. Returning to submenu.")
        return False

    if not user_input:
        print("\n[!] No configuration files provided. Audit cancelled. Returning to submenu.")
        return False

    raw_paths = [p.strip() for p in user_input.split(";") if p.strip()]
    if not raw_paths:
        print("\n[!] No valid file paths entered. Returning to submenu.")
        return False

    # Check platform safety before scanning
    if not is_linux_platform():
        print(
            f"\n[!] Sudo configuration auditing is only supported on Linux operating systems.\n"
            f"    Current platform is '{platform.system()}'. No audit performed."
        )
        return False

    print(f"\n[*] Starting sudo configuration audit on {len(raw_paths)} file path(s)...")

    try:
        findings = scan_sudo_config(raw_paths)
    except Exception as exc:
        print(f"\n[!] An error occurred during the audit: {exc}")
        return False

    if not findings:
        print("\n[*] No sudo configuration risk patterns detected in the selected accessible files.")
        print("    (Note: This does not guarantee that the overall system is secure.)")
        return True

    record_findings(session_findings, findings)
    print_findings(findings)
    return True


def print_security_audit_menu() -> None:
    """Display the security audit submenu options."""
    print("\n" + "=" * 54)
    print("                SECURITY AUDIT")
    print("=" * 54)
    print("  [1] Scan directories for SUID/SGID files")
    print("  [2] Check explicitly selected files for risky write permissions")
    print("  [3] Audit explicitly selected sudo configuration files")
    print("  [4] Return to main menu")


def run_security_audit(session_findings: Optional[list] = None) -> None:
    """Manage interactive security audit submenu loop."""
    if session_findings is None:
        session_findings = []

    while True:
        print_security_audit_menu()
        try:
            choice = input("\nSelect an audit option [1-4]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Returning to main menu.")
            break

        scan_completed = False
        if choice == "1":
            scan_completed = audit_suid_sgid(session_findings)
        elif choice == "2":
            scan_completed = audit_sensitive_permissions(session_findings)
        elif choice == "3":
            scan_completed = audit_sudo_configuration(session_findings)
        elif choice == "4":
            print("\n[*] Returning to main menu.")
            break
        else:
            print(f"\n[!] Invalid option: '{choice}'. Please select a valid option (1-4).")
            continue

        if scan_completed:
            summary = summarize_findings(session_findings)
            print("\n" + format_audit_summary(summary))


def generate_security_report(session_findings: list) -> None:
    """Generate and safely write a JSON audit report from current session findings."""
    print("\n" + "=" * 54)
    print("            SECURITY REPORT GENERATION")
    print("=" * 54)
    print(f"[*] Session Findings Collected: {len(session_findings)}")
    print("[*] Notice: Generates a JSON report containing findings")
    print("    discovered during this active application session.")
    if not session_findings:
        print("[*] Note: No findings have been recorded in this session.")
        print("    An empty audit report will be generated.")
    print("=" * 54)

    try:
        output_input = input(
            "\nEnter output report path (e.g., reports/security-report.json): "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Report generation cancelled. Returning to main menu.")
        return

    if not output_input:
        print("\n[!] No report path provided. Report generation cancelled.")
        return

    dest_path = Path(output_input)

    try:
        sys_info = collect_system_info()
    except Exception:
        sys_info = {}

    try:
        report_data = build_report_data(session_findings, system_info=sys_info)
        saved_file = save_report_to_file(report_data, dest_path, overwrite=False)
    except FileExistsError:
        print(f"\n[!] Error: Report file already exists at '{dest_path}'.")
        print("    Overwriting existing reports is not permitted by default.")
        return
    except Exception as exc:
        print(f"\n[!] Failed to save report: {exc}")
        return

    print(f"\n[+] Security report generated successfully: {saved_file}")
    print(f"    Total findings recorded: {len(session_findings)}")


def handle_choice(choice: str, session_findings: Optional[list] = None) -> bool:
    """
    Process the user menu selection.

    Returns:
        bool: True to continue the menu loop, False to exit cleanly.
    """
    if session_findings is None:
        session_findings = []

    choice = choice.strip()

    if choice == "1":
        display_system_info()
        return True
    elif choice == "2":
        run_security_audit(session_findings)
        return True
    elif choice == "3":
        generate_security_report(session_findings)
        return True
    elif choice == "4":
        print("\n[*] Exiting LPE Sentinel. Goodbye!")
        return False
    else:
        print(f"\n[!] Invalid option: '{choice}'. Please select a valid option (1-4).")
        return True


def main() -> None:
    """Run the main interactive command-line interface."""
    print_banner()
    session_findings: list = []
    running = True
    while running:
        print_menu()
        try:
            choice = input("\nSelect an option [1-4]: ")
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting LPE Sentinel. Goodbye!")
            break

        running = handle_choice(choice, session_findings)


if __name__ == "__main__":
    main()
