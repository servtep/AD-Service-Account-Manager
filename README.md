# 🛡️ AD Service Account Manager
### Enterprise Identity Lifecycle & Security Governance for Active Directory

![Version](https://img.shields.io/badge/version-1.0.0-blue?style=flat-square)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=flat-square&logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## 👤 Author

Built and Maintained with ❤️ in France by **[SERVTEP](https://servtep.com)** | Lead Architect: **[Pchelnikau Artur](https://www.linkedin.com/in/artur-pchelnikau/)**

---

**AD Service Account Manager** is an enterprise-grade PowerShell framework that codifies identity lifecycle management and eliminates *identity debt* within Active Directory. It transitions organizations away from fragmented, manual service account management into a structured, audited, and automated governance model — dramatically reducing the risk of credential-based compromise.

> Supports **Standard**, **Managed Service Accounts (MSA)**, and **Group Managed Service Accounts (gMSA)** — with native hybrid coverage via Microsoft Graph / Entra ID.

---

## 📋 Table of Contents

- [Strategic Overview](#-strategic-overview)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [CLI Reference](#-cli-reference)
- [Modules](#-modules)
- [Security Engine](#-security-engine)
- [Audit & Compliance](#-audit--compliance)

---

## 🎯 Strategic Overview

| Operational Objective | Functional Component | Mitigated Risk |
|---|---|---|
| Lifecycle Management | Provisioning (Wizard, Clone, Bulk CSV) | Unauthorized Account Creation & Identity Debt |
| Security Hardening | Proactive Attack Surface Scanning | Credential Theft (Kerberoasting, AS-REP) |
| Dependency Mapping | WMI/WS-Man Discovery (Service, Task, IIS) | Service Downtime during Rotation/Decommissioning |
| Privilege Governance | Shadow Admin & AdminSDHolder Auditing | Persistent Backdoors & Domain Escalation |
| Integrity Auditing | SHA-256 Hashed Logs & SIEM Export | Compliance Failures & Log Tampering |

---

## 🔧 Prerequisites

### Required Modules
| Module | Status | Purpose |
|---|---|---|
| `PowerShell 5.1+` | ✅ Required | Core runtime |
| `RSAT ActiveDirectory` | ✅ Required | AD operations & LDAP filtering |
| `Microsoft.Graph` | ⚪ Optional | Entra ID / hybrid cloud coverage |
| `WebAdministration` | ⚪ Optional | IIS App Pool dependency scanning |
| `GroupPolicy` | ⚪ Optional | GPO impact analysis & gpresult |

> **Microsoft Graph Scopes:** `Application.Read.All` · `Directory.Read.All` · `AppRoleAssignment.Read.All`

### Permissions Model

| Role | Access Level |
|---|---|
| `ReadOnly` | Scans, inventory, and health auditing |
| `DelegatedAdmin / AccountOperator` | Write operations (Create, Modify, Delete) on specific OUs |
| `DomainAdmin` | Forest-wide security sweeps & AdminSDHolder auditing |
| `Local Administrator` | Dependency mapping via WMI/CIM and Task Scheduler on target servers |

> ⚠️ **SMTP Security Notice:** SMTP credentials are encrypted with **Windows DPAPI**, bound strictly to the user account and machine where the configuration was performed. If running as a Scheduled Task, the task identity **must** match the identity used during SMTP setup.

---

## 🚀 Quick Start

```powershell
# Launch the full interactive management console
.\AD-Service-Account-Manager.ps1

# Execute a non-interactive security scan and email findings
.\AD-Service-Account-Manager.ps1 -Mode SecurityScan -SmtpAlert

# Run a forest-wide inventory in safe simulation mode
.\AD-Service-Account-Manager.ps1 -Mode Inventory -Forest -DryRun

# Register a weekly drift-detection scheduled task (Monday at 02:00)
.\AD-Service-Account-Manager.ps1 -Mode DriftCheck -SmtpAlert
```

---

## 💻 CLI Reference

| Parameter | Values / Usage | Outcome |
|---|---|---|
| `-Mode` | `Audit` | Exports HTML reports and SIEM-ready JSON logs |
| | `SecurityScan` | Executes high-priority sweeps (Kerberoasting, AS-REP, etc.) |
| | `Inventory` | Full domain discovery with data export |
| | `DriftCheck` | Detects unauthorized mutations vs. baseline |
| | `HealthCheck` | Audits stale status, lockouts, and account health |
| `-Domain` | FQDN (e.g., `corp.local`) | Targets a specific domain; defaults to local |
| `-Forest` | Switch | Scans all domains in the forest topology |
| `-DryRun` | Switch | Simulates write logic with `[WHATIF]`; zero AD changes |
| `-ReadOnly` | Switch | Hard-locks session; blocks all modification options |
| `-SmtpAlert` | Switch | Dispatches email report after non-interactive run |

> 💡 **Safety Flags:** `-DryRun` processes write-logic paths while prefixing actions with `[WHATIF]`. `-ReadOnly` is a session-level guardrail that **completely blocks** creation and modification commands from the console UI.

---

## 📦 Modules

### Provisioning & Lifecycle Management
- **Single Account Wizard** — Guided creation for Standard, MSA, and gMSA accounts with KDS Root Key verification
- **Account Cloning** — Replicates Description, OU placement, and group memberships for functional parity
- **Bulk CSV Import** — Mass provisioning with enforced `sAMAccountName` max length (20 chars), automatic illegal character sanitization, and batch **Rollback** support

### Dependency Mapping
Before any modification or deletion, the tool queries remote hosts to prevent service outages:

| Protocol | Target | Ports |
|---|---|---|
| WMI / CIM | Windows Services | 135 |
| WS-Man / PSRemoting | Scheduled Tasks, IIS App Pools | 5985 / 5986 |

### Computer Account Auditing
Flags non-standard SPNs on computer objects and audits **unconstrained delegation** on non-DC machines — closing a common visibility gap in hybrid environments.

---

## 🔍 Security Engine

The security module is a proactive defense engine designed to uncover legacy vulnerabilities and sophisticated persistence mechanisms.

### Attack Surface Checks

| Threat Vector | Detection Logic | Risk Level |
|---|---|---|
| **Kerberoasting** | Accounts with SPNs using RC4 encryption or `adminCount=1` | 🔴 Critical |
| **AS-REP Roasting** | Accounts with Kerberos pre-auth disabled | 🔴 Critical |
| **Unconstrained Delegation** | Accounts capable of stealing TGTs from any authenticating user | 🔴 Critical |
| **SID History** | Legacy SIDs from previous domains granting hidden elevated privileges | 🟠 High |

### Shadow Admin & AdminSDHolder Persistence
Detects accounts with `adminCount=1` no longer in privileged groups, and performs **AdminSDHolder ACE comparisons** to uncover red-team backdoors that survive the hourly SDProp reset.

### Modern Hardening
- **Credential Guard Compatibility** — Identifies accounts relying on NTLM or Unconstrained Delegation (blocked by VBS)
- **Protected Users Impact** — Flags service accounts at risk from the group's 4-hour TGT lifetime or AES-only enforcement

---

## 📊 Audit & Compliance

Compliant with **CIS**, **NIST SP 800-53**, and **ISO 27001** frameworks.

### Tamper-Evident Logging
Every write operation recomputes a **SHA-256 hash** of the CSV audit log, stored alongside the log as a `.sha256` file. Any unauthorized modification to the audit trail is detected on the next review cycle.

### Drift Detection
Establish a **Baseline Snapshot** (stored as JSON in `%APPDATA%\ADSvcAcctMgr`) and run subsequent scans to detect unauthorized account creations, OU moves, or changes to security flags.

### Reporting & SIEM Integration
| Format | Target |
|---|---|
| **HTML** | Rich dark-mode reports with dynamic compliance cross-references (CIS L1, NIST AC-2) |
| **JSON** | Native SIEM ingestion |
| **CEF** | Splunk / QRadar |
| **Syslog** | Centralized log aggregation |

---

## 👤 Author

Built and Maintained with ❤️ in France by **[SERVTEP](https://servtep.com)** | Lead Architect: **[Pchelnikau Artur](https://www.linkedin.com/in/artur-pchelnikau/)**

---

<p align="center"><sub>AD Service Account Manager v1.0.0 · Built for enterprise identity security</sub></p>
