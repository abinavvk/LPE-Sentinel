"""
Advisory Remediation Guidance Module for LPE Sentinel.

Provides deterministic, defensive, and evidence-supported remediation advice
for identified security findings. Adheres to strict least-privilege principles:
- Never generates exploit commands, payloads, or privilege escalation hints.
- Never claims a binary or configuration is exploitable without direct proof.
- Does not modify scanner finding models, severities, or persistent records.
- Provides safe, verifiable steps: Why it matters, Investigation, Remediation, Validation.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Union

try:
    from lpe_sentinel.models import Finding
except ImportError:
    from models import Finding


@dataclass(frozen=True)
class RemediationGuidance:
    """
    Structured advisory remediation guidance for a security finding.

    Attributes:
        finding_id: Identifier of the associated finding or pattern.
        category: High-level classification category.
        why_it_matters: Security explanation of the defensive risk.
        investigation_steps: Safe diagnostic queries to assess operational context.
        remediation_steps: Recommended hardening actions following least privilege.
        validation_steps: Verification commands to confirm the issue is addressed.
    """

    finding_id: str
    category: str
    why_it_matters: str
    investigation_steps: List[str]
    remediation_steps: List[str]
    validation_steps: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert guidance to standard dictionary representation."""
        return asdict(self)


# Predefined, vetted advisory guidance mapping for supported finding categories
_KNOWN_GUIDANCE: Dict[str, Dict[str, Any]] = {
    "SUID-001": {
        "category": "SUID / SGID Executables",
        "why_it_matters": (
            "Files with the SUID (Set Owner User ID) bit execute with the privileges of the file owner "
            "(typically root) rather than the invoking user. If a SUID binary has configuration flaws, "
            "unexpected features, or command-injection paths, local users might perform actions outside "
            "their authorized security context."
        ),
        "investigation_steps": [
            "Verify whether the binary is an official component of the installed distribution package (e.g., using 'dpkg -S <path>' on Debian/Ubuntu or 'rpm -qf <path>' on RHEL/Fedora).",
            "Review administrative policies and operational documentation to determine if non-privileged users legitimately require execution access.",
            "Inspect the file owner and permission mode using 'stat <path>' or 'ls -l <path>'.",
        ],
        "remediation_steps": [
            "If elevated execution is not strictly required for standard users, remove the SUID permission bit using: chmod u-s <path>",
            "If execution is only required by administrators, restrict group ownership and remove world-executable permissions (e.g., chown root:admin_group <path>; chmod 4750 <path>).",
            "Consider replacing legacy SUID executables with granular Linux capabilities (e.g., setcap) where supported by the service.",
        ],
        "validation_steps": [
            "Inspect file attributes with 'ls -l <path>' to confirm the 's' bit is removed from the user permissions field (mode should reflect standard execution rights).",
            "Verify that authorized administrative workflows still function under standard or sudo-based privileges.",
        ],
    },
    "SUID-002": {
        "category": "SUID / SGID Executables",
        "why_it_matters": (
            "The detected binary matches a known dual-use utility (such as a command shell, script interpreter, "
            "editor, or system tool) configured with SUID permissions. While not proof of an active vulnerability, "
            "dual-use utilities often have built-in capabilities to spawn subshells, read arbitrary files, or execute "
            "helper commands that retain the elevated owner privileges."
        ),
        "investigation_steps": [
            "Confirm why this specific standard utility was assigned SUID privileges.",
            "Check system audit logs for invocations of this binary by unprivileged user accounts.",
            "Verify package manager integrity for the binary (e.g., 'debsums -s' or 'rpm -V <package>').",
        ],
        "remediation_steps": [
            "Standard dual-use utilities (shells, interpreters, editors) should never have SUID enabled. Remove the bit immediately: chmod u-s <path>",
            "If specific users need elevated access to perform tasks with this tool, configure explicit, restricted entries in /etc/sudoers.d/ instead of global SUID permissions.",
            "Ensure the binary is stored on a filesystem mounted with 'nosuid' if elevated execution is unnecessary for that volume.",
        ],
        "validation_steps": [
            "Run 'stat -c \"%a %n\" <path>' and verify the octal permissions do not include the 4000 (SUID) bit.",
            "Test execution from an unprivileged test account to ensure the process runs with the caller's standard UID/GID.",
        ],
    },
    "SGID-001": {
        "category": "SUID / SGID Executables",
        "why_it_matters": (
            "Files with the SGID (Set Group ID) bit execute with the privileges of the file's owning group. "
            "If the owning group has access to sensitive files, devices, or network sockets, an unprivileged user "
            "executing the binary might gain unauthorized read or write access to those group-managed resources."
        ),
        "investigation_steps": [
            "Identify the owning group of the file and inspect what resources, directories, or devices that group can access.",
            "Check whether the application requires group privileges for operational logging, lock files, or inter-process communication.",
            "Verify if the binary is provided by a verified system package.",
        ],
        "remediation_steps": [
            "If elevated group rights are unnecessary, remove the SGID permission bit: chmod g-s <path>",
            "If group execution is required, ensure the group only possesses the minimal necessary permissions on specific data files, not broad system access.",
        ],
        "validation_steps": [
            "Verify with 'ls -l <path>' that the 's' character is absent from the group permissions field.",
            "Confirm related services operate normally without encountering group permission errors.",
        ],
    },
    "SGID-002": {
        "category": "SUID / SGID Executables",
        "why_it_matters": (
            "A standard dual-use utility was discovered with SGID permissions enabled. If the binary can manipulate "
            "files or spawn child processes, callers may be able to read, modify, or create files with the privileges "
            "of the assigned group."
        ),
        "investigation_steps": [
            "Determine what group owns the binary and whether members of that group can write to sensitive system files.",
            "Inspect how the file was deployed (manual script, package, or third-party installer).",
        ],
        "remediation_steps": [
            "Remove the SGID bit from the dual-use binary: chmod g-s <path>",
            "Substitute with role-based access control or dedicated daemon architecture with minimal permissions.",
        ],
        "validation_steps": [
            "Inspect permissions with 'ls -l <path>' to confirm the SGID bit is removed.",
            "Confirm that normal users cannot invoke the utility with inherited group rights.",
        ],
    },
    "PERM-001": {
        "category": "File & Directory Permissions",
        "why_it_matters": (
            "The target file is configured with world-writable permissions (mode bit 'o+w'), allowing any local account "
            "on the system to modify, overwrite, or truncate its contents. If the file is a system configuration, script, "
            "cron job, or service unit, unauthorized tampering can directly alter system behavior or lead to privilege escalation."
        ),
        "investigation_steps": [
            "Identify what processes, background daemons, or scheduled tasks read or execute this file.",
            "Check file modification history, backup copies, and file integrity to detect any unauthorized changes.",
            "Review whether the world-writable mode was introduced by an overly permissive umask or deployment script.",
        ],
        "remediation_steps": [
            "Remove world-writable permissions immediately: chmod o-w <path>",
            "Set appropriate restrictive ownership and mode (e.g., chown root:root <path>; chmod 644 <path> or chmod 600 <path> for sensitive data).",
            "Verify that parent directories also restrict write access to authorized users only.",
        ],
        "validation_steps": [
            "Run 'stat -c \"%a %n\" <path>' and verify the last octal digit (other permissions) does not contain write permissions (bits 2, 3, 6, or 7).",
            "Verify that authorized services can still read the configuration cleanly.",
        ],
    },
    "PERM-002": {
        "category": "File & Directory Permissions",
        "why_it_matters": (
            "The file permits write access to members of its owning group. If non-administrative users or shared service accounts "
            "belong to this group, they can modify system configurations or executables, circumventing access control boundaries."
        ),
        "investigation_steps": [
            "Enumerate all accounts belonging to the file's owning group using 'getent group <groupname>'.",
            "Assess whether group write access is an intentional design choice for collaborative administration or an artifact of default creation permissions.",
        ],
        "remediation_steps": [
            "Remove group write permissions if not strictly required: chmod g-w <path>",
            "If collaborative editing is required, audit group membership to ensure only authorized administrators belong to the group, or use POSIX ACLs ('setfacl') for fine-grained control.",
        ],
        "validation_steps": [
            "Run 'ls -l <path>' and verify that the group permissions field displays 'r--' or 'r-x', without 'w'.",
            "Confirm that service processes continue operating without permission denials.",
        ],
    },
    "SUDO-001": {
        "category": "Sudo Configuration",
        "why_it_matters": (
            "The sudoers rule includes the 'NOPASSWD' tag, permitting users to execute designated commands with elevated "
            "privileges without entering their password. If the target executable allows shell escapes, file edits, or argument "
            "manipulation, or if the user's local session is compromised, an attacker can escalate privileges without credential challenge."
        ),
        "investigation_steps": [
            "Inspect the complete rule in /etc/sudoers or /etc/sudoers.d/ using 'visudo -c' to locate the directive.",
            "Determine whether the command is invoked by automated non-interactive automation (e.g., CI/CD agents or backup scripts) or interactive users.",
            "Check if the permitted binary has built-in features that could allow arbitrary execution or file writing.",
        ],
        "remediation_steps": [
            "Require password authentication for interactive administrative users by removing the 'NOPASSWD:' tag from the rule.",
            "If non-interactive automation strictly requires passwordless execution, restrict the allowed arguments explicitly and avoid permitting generic shells or interpreters.",
            "Always use 'visudo -f <file>' to make edits so syntax is validated before saving.",
        ],
        "validation_steps": [
            "Run 'visudo -c' to confirm the sudoers configuration syntax is strictly valid.",
            "Test invocation with 'sudo -l -U <username>' to confirm the updated rule is in effect and password prompts occur as expected.",
        ],
    },
    "SUDO-002": {
        "category": "Sudo Configuration",
        "why_it_matters": (
            "The sudo rule permits execution of 'ALL' commands. While common for full system administrators, blanket 'ALL' "
            "access circumvents the principle of least privilege. If assigned to non-root service accounts or broad groups, "
            "it grants unrestricted root control."
        ),
        "investigation_steps": [
            "Verify whether the affected user or group actually requires unrestricted root access or only a small set of administrative utilities.",
            "Review sudoers audit logs (/var/log/auth.log or journalctl) to see which commands the account typically executes.",
        ],
        "remediation_steps": [
            "Replace unrestricted 'ALL' with explicit, absolute paths to the specific required commands.",
            "Avoid wildcard parameters and disallow shell-escape binaries.",
            "Enforce dual-control or centralized privileged access management for full administrative operations.",
        ],
        "validation_steps": [
            "Check configuration with 'visudo -c' and run 'sudo -l -U <username>' to verify the rule restricts commands to explicit binaries.",
        ],
    },
    "SUDO-003": {
        "category": "Sudo Configuration",
        "why_it_matters": (
            "The sudo rule contains wildcard characters ('*') in the command path or parameter specification. "
            "Wildcards in sudoers can lead to unexpected command execution because wildcards can match path traversal "
            "sequences (such as '../../bin/sh') or unexpected options that override command behavior."
        ),
        "investigation_steps": [
            "Locate the wildcard rule in /etc/sudoers or /etc/sudoers.d/.",
            "Analyze how the command parses command-line flags and whether wildcard expansion could permit unintended argument injection.",
        ],
        "remediation_steps": [
            "Replace wildcard parameters with explicit allowable subcommands or separate rule lines for each permitted operation.",
            "If variable arguments are necessary, wrap the command in a secure, non-writable shell script owned by root with fixed argument parsing.",
            "Always use 'visudo' when modifying sudo configuration files.",
        ],
        "validation_steps": [
            "Run 'visudo -c' to verify sudoers syntax.",
            "Run 'sudo -l -U <username>' and confirm that wildcards are eliminated in favor of explicit specifications.",
        ],
    },
}

# Generic fallback for unknown or uncataloged finding categories
_GENERIC_GUIDANCE = {
    "category": "General Security Review",
    "why_it_matters": (
        "This security finding indicates a configuration or permission attribute that warrants administrative review. "
        "Adhering to baseline hardening standards reduces the attack surface and helps maintain least privilege."
    ),
    "investigation_steps": [
        "Review the finding description, affected resource path, and supporting evidence carefully.",
        "Check system documentation and security baselines (such as CIS benchmarks) applicable to this resource.",
        "Assess whether the configuration represents an intentional operational exception or an unintended drift.",
    ],
    "remediation_steps": [
        "Apply the principle of least privilege: restrict file permissions, remove unnecessary privileges, and constrain access.",
        "If the configuration is required for operational reasons, document the business justification in an approved security exception record.",
        "Follow standard administrative change control procedures before altering system settings.",
    ],
    "validation_steps": [
        "Re-run the LPE-Sentinel audit to verify whether the finding is resolved or updated.",
        "Confirm that normal system operations and legitimate services continue functioning as expected.",
    ],
}


def get_remediation_guidance(finding: Union[Finding, Dict[str, Any]]) -> RemediationGuidance:
    """
    Look up defensive advisory remediation guidance for a security finding.

    Deterministic, testable, and completely independent of web templates.
    Never modifies the original Finding instance, dictionary, or its severity.

    Args:
        finding: Finding dataclass instance or dictionary with at least 'finding_id'.

    Returns:
        RemediationGuidance instance containing vetted defensive recommendations.
    """
    if isinstance(finding, dict):
        finding_id = str(finding.get("finding_id", "UNKNOWN")).strip()
    elif hasattr(finding, "finding_id"):
        finding_id = str(getattr(finding, "finding_id", "UNKNOWN")).strip()
    else:
        finding_id = "UNKNOWN"

    # Normalize finding_id to upper case
    normalized_id = finding_id.upper()

    if normalized_id in _KNOWN_GUIDANCE:
        data = _KNOWN_GUIDANCE[normalized_id]
        return RemediationGuidance(
            finding_id=finding_id,
            category=data["category"],
            why_it_matters=data["why_it_matters"],
            investigation_steps=list(data["investigation_steps"]),
            remediation_steps=list(data["remediation_steps"]),
            validation_steps=list(data["validation_steps"]),
        )

    # Prefix-based category fallback (e.g., SUID-xxx, SGID-xxx, PERM-xxx, SUDO-xxx)
    if normalized_id.startswith("SUID-"):
        base_data = _KNOWN_GUIDANCE["SUID-001"]
        return RemediationGuidance(
            finding_id=finding_id,
            category="SUID Executables",
            why_it_matters=base_data["why_it_matters"],
            investigation_steps=list(base_data["investigation_steps"]),
            remediation_steps=list(base_data["remediation_steps"]),
            validation_steps=list(base_data["validation_steps"]),
        )
    elif normalized_id.startswith("SGID-"):
        base_data = _KNOWN_GUIDANCE["SGID-001"]
        return RemediationGuidance(
            finding_id=finding_id,
            category="SGID Executables",
            why_it_matters=base_data["why_it_matters"],
            investigation_steps=list(base_data["investigation_steps"]),
            remediation_steps=list(base_data["remediation_steps"]),
            validation_steps=list(base_data["validation_steps"]),
        )
    elif normalized_id.startswith("PERM-"):
        base_data = _KNOWN_GUIDANCE["PERM-001"]
        return RemediationGuidance(
            finding_id=finding_id,
            category="File Permissions",
            why_it_matters=base_data["why_it_matters"],
            investigation_steps=list(base_data["investigation_steps"]),
            remediation_steps=list(base_data["remediation_steps"]),
            validation_steps=list(base_data["validation_steps"]),
        )
    elif normalized_id.startswith("SUDO-"):
        base_data = _KNOWN_GUIDANCE["SUDO-001"]
        return RemediationGuidance(
            finding_id=finding_id,
            category="Sudo Configuration",
            why_it_matters=base_data["why_it_matters"],
            investigation_steps=list(base_data["investigation_steps"]),
            remediation_steps=list(base_data["remediation_steps"]),
            validation_steps=list(base_data["validation_steps"]),
        )

    # Generic fallback for unknown finding types
    return RemediationGuidance(
        finding_id=finding_id,
        category=_GENERIC_GUIDANCE["category"],
        why_it_matters=_GENERIC_GUIDANCE["why_it_matters"],
        investigation_steps=list(_GENERIC_GUIDANCE["investigation_steps"]),
        remediation_steps=list(_GENERIC_GUIDANCE["remediation_steps"]),
        validation_steps=list(_GENERIC_GUIDANCE["validation_steps"]),
    )
