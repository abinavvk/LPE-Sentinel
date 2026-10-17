"""
Synthetic Demo Data Generator for LPE Sentinel Web Dashboard.

Provides safely constructed, explicitly labeled demonstration findings
for UI preview and testing. NEVER represents a live host scan.
"""

from typing import Any, Dict, List

try:
    from lpe_sentinel.audit_summary import summarize_findings
    from lpe_sentinel.models import Finding
except ImportError:
    from audit_summary import summarize_findings
    from models import Finding

DEMO_DISCLAIMER = (
    "SIMULATED DEMO DATA: These findings are synthetic test fixtures and DO NOT "
    "represent an active or live scan of this host. No actual binaries were inspected "
    "or executed."
)


def get_demo_findings() -> List[Finding]:
    """
    Return a curated list of synthetic demonstration findings.

    Every finding title and description is explicitly prefixed to make it
    impossible to mistake demo data for genuine audit findings.
    """
    return [
        Finding(
            finding_id="SUID-001",
            title="[SIMULATED DEMO] SUID Permission Bit Detected on Executable",
            severity="INFO",
            description=(
                "[SIMULATED DEMO] Synthetic finding representing an executable file with SUID "
                "(Set Owner User ID upon execution) bit set. In a real audit, this indicates "
                "the binary runs with file owner privileges."
            ),
            evidence="Mode: 0o104755 (-rwsr-xr-x) | Owner: root:root [SYNTHETIC TEST EVIDENCE]",
            affected_resource="/demo/mock/bin/sample_suid_tool",
            recommendation=(
                "Review whether elevated SUID permissions are required. If not, remove "
                "the bit using: chmod u-s /path/to/binary"
            ),
            mitre_attack="T1548.001",
        ),
        Finding(
            finding_id="SUID-002",
            title="[SIMULATED DEMO] High-Risk SUID Binary Review Recommended: bash",
            severity="HIGH",
            description=(
                "[SIMULATED DEMO] Synthetic finding representing a standard command interpreter "
                "discovered with SUID permissions. SUID shells allow callers to launch subshells "
                "retaining owner privileges."
            ),
            evidence="Binary: bash | Category: Command Shell | File: /demo/mock/bin/bash | Special Bits: SUID [SYNTHETIC]",
            affected_resource="/demo/mock/bin/bash",
            recommendation="Ensure interactive shells never have SUID/SGID enabled. Remove using: chmod u-s /demo/mock/bin/bash",
            mitre_attack="T1548.001",
        ),
        Finding(
            finding_id="PERM-001",
            title="[SIMULATED DEMO] World-Writable Sensitive Configuration File",
            severity="HIGH",
            description=(
                "[SIMULATED DEMO] Synthetic finding representing a critical system file that "
                "grants write access to all local users. In real systems, this could allow "
                "unauthorized privilege alteration."
            ),
            evidence="Permissions: -rw-rw-rw- (0o666) | File: /demo/mock/etc/dummy_passwd [SYNTHETIC]",
            affected_resource="/demo/mock/etc/dummy_passwd",
            recommendation="Restrict permissions so only the root owner can modify the file: chmod 644 /demo/mock/etc/dummy_passwd",
            mitre_attack="T1548.001",
        ),
        Finding(
            finding_id="PERM-002",
            title="[SIMULATED DEMO] Group-Writable System File",
            severity="MEDIUM",
            description=(
                "[SIMULATED DEMO] Synthetic finding representing a file writable by members "
                "of its associated UNIX group."
            ),
            evidence="Permissions: -rw-rw-r-- (0o664) | Group: staff [SYNTHETIC]",
            affected_resource="/demo/mock/etc/sample_app.conf",
            recommendation="Verify group membership and remove group write bit if unnecessary: chmod g-w /demo/mock/etc/sample_app.conf",
            mitre_attack="T1548.001",
        ),
        Finding(
            finding_id="SUDO-001",
            title="[SIMULATED DEMO] NOPASSWD Privilege Specification in Sudoers",
            severity="MEDIUM",
            description=(
                "[SIMULATED DEMO] Synthetic finding representing a sudoers rule configured "
                "with the NOPASSWD tag, allowing passwordless command execution."
            ),
            evidence="Rule Pattern: NOPASSWD: /usr/bin/apt-get [SYNTHETIC EVIDENCE - NO SECRETS]",
            affected_resource="/demo/mock/etc/sudoers.d/demo_rule",
            recommendation="Require password re-authentication for privileged command execution where feasible.",
            mitre_attack="T1548.003",
        ),
    ]


def get_demo_audit_payload() -> Dict[str, Any]:
    """
    Return a complete, validated audit payload dictionary representing DEMO mode.

    Contains synthetic findings, calculated summary metrics, system metadata,
    and unmistakable simulation watermarks.
    """
    findings = get_demo_findings()
    summary = summarize_findings(findings)

    findings_dicts = []
    for f in findings:
        f_dict = f.to_dict()
        f_dict["is_demo"] = True
        f_dict["is_simulated"] = True
        findings_dicts.append(f_dict)

    return {
        "is_demo": True,
        "is_simulated": True,
        "demo_watermark": "SIMULATED DEMO DATA — NOT A LIVE AUDIT",
        "disclaimer": DEMO_DISCLAIMER,
        "status": "COMPLETED (DEMO SIMULATION)",
        "is_complete": True,
        "system_info": {
            "os_name": "Linux (Simulation)",
            "release": "6.6.0-kali-simulated",
            "hostname": "sentinel-demo-host",
            "username": "demo-operator",
            "architecture": "x86_64",
            "python_version": "3.14.7",
            "platform_category": "Linux (Demo Mode)",
        },
        "summary": summary,
        "findings": findings_dicts,
        "scanner_results": {
            "suid_sgid": {
                "scanner_name": "suid_sgid",
                "status": "COMPLETED (DEMO)",
                "findings_count": 2,
                "target_paths": ["/demo/mock/bin"],
                "accessible_paths": ["/demo/mock/bin"],
                "skipped_paths": [],
                "message": "Demo simulation: 2 synthetic SUID/SGID findings generated.",
            },
            "sensitive_permissions": {
                "scanner_name": "sensitive_permissions",
                "status": "COMPLETED (DEMO)",
                "findings_count": 2,
                "target_paths": ["/demo/mock/etc/dummy_passwd", "/demo/mock/etc/sample_app.conf"],
                "accessible_paths": ["/demo/mock/etc/dummy_passwd", "/demo/mock/etc/sample_app.conf"],
                "skipped_paths": [],
                "message": "Demo simulation: 2 synthetic permission findings generated.",
            },
            "sudo_audit": {
                "scanner_name": "sudo_audit",
                "status": "COMPLETED (DEMO)",
                "findings_count": 1,
                "target_paths": ["/demo/mock/etc/sudoers.d/demo_rule"],
                "accessible_paths": ["/demo/mock/etc/sudoers.d/demo_rule"],
                "skipped_paths": [],
                "message": "Demo simulation: 1 synthetic sudoers finding generated.",
            },
        },
        "errors": [],
    }
