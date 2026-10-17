# LPE Sentinel — Project Scope & Ethical Guidelines

## 1. Project Mission

**LPE Sentinel** is an educational, defensive cybersecurity project designed to assist system administrators, security auditors, and students in evaluating the privilege escalation posture of Linux operating systems.

---

## 2. Core Operational Scope

The toolkit operates strictly within defensive and audit boundaries:

### 2.1 Defensive Auditing Only
* **Read-Only / Passive Inspections:** All scanner modules strictly perform read-only checks (inspecting configuration files, permissions, running processes, kernel versions, and installed binaries).
* **Clear Reporting:** Findings are categorized by severity and risk level to provide actionable visibility into system weaknesses.

### 2.2 No Exploitation or Weaponization
* **Zero Payloads:** The toolkit does not incorporate exploits, rootkits, shellcode, reverse shells, or weaponized proof-of-concept (PoC) code.
* **No Privilege Escalation Attempts:** The toolkit will never attempt to execute commands with elevated privileges, manipulate permissions, or bypass security controls.

### 2.3 No Automatic Remediation
* **Non-Destructive:** The toolkit will not modify system configurations, rewrite file permissions, or alter `/etc/sudoers` or cron jobs automatically.
* **Human-in-the-Loop:** All remediation decisions remain solely with the authorized system owner or administrator.

---

## 3. Rules of Engagement & Ethical Usage

* **Authorization Required:** This toolkit must only be run on systems you own or on systems where you have received explicit, written permission from the system owner (e.g., dedicated testing VMs, CTF labs, or approved educational sandbox environments).
* **No Unauthorized Network Use:** Never deploy or run this toolkit on unapproved corporate, institutional, or third-party infrastructure.
* **Safe Testing Environment:** Recommended testing should always be conducted in an isolated sandbox, such as a Kali Linux virtual machine running inside VirtualBox.

---

## 4. Summary Matrix

| Capability | In Scope? | Notes |
| :--- | :---: | :--- |
| Read configuration files | ✅ Yes | Auditing `/etc/passwd`, `/etc/crontab`, etc. |
| Check SUID/SGID binaries | ✅ Yes | Identifies potentially exploitable binaries |
| Check sudo rules | ✅ Yes | Inspects user sudo permissions (read-only) |
| Attempt root access | ❌ No | Strictly forbidden |
| Execute exploit scripts | ❌ No | Strictly forbidden |
| Modify system files | ❌ No | Remediation guidance provided in reports only |
