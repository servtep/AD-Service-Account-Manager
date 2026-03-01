#Requires -Modules ActiveDirectory
#Requires -Version 5.1

<#
.SYNOPSIS
    AD Service Account Manager v1.0.0
    A comprehensive, production-ready tool for managing Active Directory service accounts.

.DESCRIPTION
    This script provides a full lifecycle management console for Active Directory service
    accounts, including Standard user-based accounts, Managed Service Accounts (MSA), and
    Group Managed Service Accounts (gMSA).

    Core capabilities:
      CREATE    - Wizard-driven single account creation, account cloning, and bulk CSV import.
      MANAGE    - Enable/disable, unlock, password reset, bulk rotation, SPN management,
                  group assignments, OU moves, account expiry, Recycle Bin restore,
                  and AD replication verification.
      TEST      - Health checks, password status, duplicate/conflict SPN detection,
                  gMSA retrieval tests, MSA host binding validation, Kerberos delegation
                  review, privileged group scanning, stale/never-logged-on/aging reports,
                  naming compliance, and bulk OU status.
      SECURITY  - Kerberoastable account detection, AS-REP Roasting exposure, full delegation
                  sweep, PASSWD_NOTREQD scan, reversible encryption scan, shadow admin
                  detection (adminCount=1), SID History scan, weak Kerberos encryption,
                  logon workstation audits, ACL auditing, AdminSDHolder comparison, Protected
                  Users impact, and Credential Guard compatibility.
      DEPENDENCY- Windows Services, Scheduled Tasks, and IIS Application Pool dependency
                  mapping — run before any modification or deletion.
      VIRTUAL   - Discovery and baseline comparison of NT SERVICE\*, SYSTEM, LocalService,
                  and NetworkService identities on Windows hosts.
      AZURE AD  - Microsoft Graph-powered Service Principal inventory, credential expiry
                  alerts, ownership gaps, and high-privilege permission detection.
      COMPUTERS - Computer accounts acting as service identities: non-standard SPNs,
                  delegation configuration, and stale computer service accounts.
      GPO       - Group Policy impact analysis: effective GPOs, password policy GPOs,
                  logon-right restrictions, and GPO-managed service credentials.
      MULTI-FOREST - Cross-domain and cross-forest inventory, security scanning, and
                  health auditing; trusted-forest configuration support.
      INVENTORY - Full domain discovery (all account types), health audits, and HTML/CSV
                  export reports.
      AUDIT     - SHA-256 integrity-protected audit log, SIEM export (JSON/CEF/Syslog),
                  HTML audit report with compliance cross-references, AD security event
                  log reading, baseline snapshots, drift detection, and change history.
      SETTINGS  - SMTP configuration (DPAPI-encrypted passwords), naming conventions,
                  thresholds, page size, privileged group list, compliance framework,
                  trusted forests, and SMTP timeout/retry tuning.

    Non-interactive modes (schedulable):
      Audit, SecurityScan, Inventory, DriftCheck, HealthCheck

    Safety features:
      -DryRun     Preview all write operations without committing any AD changes.
      -ReadOnly   Disable all write operations for the current session.
      -SmtpAlert  Send email report after non-interactive runs.

.PARAMETER Mode
    Execution mode. Default is Interactive (full menu-driven console).
    Non-interactive values: Audit | SecurityScan | Inventory | DriftCheck | HealthCheck

.PARAMETER OutputPath
    Override output directory for non-interactive report files.
    Defaults to %APPDATA%\ADSvcAcctMgr\reports.

.PARAMETER Domain
    Target domain FQDN. Leave empty to auto-detect the current domain.

.PARAMETER Forest
    When specified, scope multi-forest operations to the entire forest.

.PARAMETER DryRun
    Preview mode. All write operations are logged as WHATIF and not executed.

.PARAMETER ReadOnly
    Enforces a read-only session. All create/modify/delete options are blocked.

.PARAMETER SmtpAlert
    Triggers an email alert at the end of non-interactive runs.

.EXAMPLE
    # Launch the interactive console
    .\AD-Service-Account-Manager.ps1

.EXAMPLE
    # Run a security scan and email results
    .\AD-Service-Account-Manager.ps1 -Mode SecurityScan -SmtpAlert

.EXAMPLE
    # Run a full inventory against a specific domain in dry-run mode
    .\AD-Service-Account-Manager.ps1 -Mode Inventory -Domain corp.local -DryRun

.EXAMPLE
    # Register a weekly drift-detection scheduled task (run interactively first to set SMTP)
    .\AD-Service-Account-Manager.ps1  # → Audit → Register scheduled task

.NOTES
    Author      : (Artur Pchelnikau / SERVTEP)
    Created     : 2026
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, RSAT ActiveDirectory module
    Optional    : GroupPolicy module (RSAT), Microsoft.Graph (Azure AD features),
                  WebAdministration module (IIS dependency scan)

    IMPORTANT — DPAPI password encryption:
      The SMTP password is encrypted with Windows DPAPI, which is tied to the Windows
      user account and machine that ran the encryption. The password cannot be decrypted
      by a different user or on a different machine. If running as a scheduled task, ensure
      the task runs under the same user account that configured SMTP.

    SECURITY NOTE:
      This script can expose sensitive account information. Restrict access to the script
      file and the %APPDATA%\ADSvcAcctMgr directory. Audit logs contain operator names
      and action details — protect them accordingly.
#>

param(
    # Execution mode — Interactive launches the full menu console
    [ValidateSet("Interactive","Audit","SecurityScan","Inventory","DriftCheck","HealthCheck")]
    [string]$Mode = "Interactive",

    # Optional override for report output directory
    [string]$OutputPath = "",

    # Target domain FQDN; empty = auto-detect from current environment
    [string]$Domain = "",

    # Scope multi-forest operations to the entire forest topology
    [switch]$Forest,

    # Preview all writes without committing; zero AD changes
    [switch]$DryRun,

    # Block ALL write operations for this session
    [switch]$ReadOnly,

    # Send email report after non-interactive runs (requires SMTP config)
    [switch]$SmtpAlert
)

# Strict mode catches uninitialised variables, bad property access, etc.
Set-StrictMode -Version Latest

# Stop on all terminating errors so callers can catch failures cleanly
$ErrorActionPreference = "Stop"

# ══════════════════════════════════════════════════════════════════════════════
#  GLOBALS — Application paths, version, and runtime state
# ══════════════════════════════════════════════════════════════════════════════

# Script version identifier, shown in banners and audit log entries
$SCRIPT_VERSION = "1.0.0"

# Root application data directory — stores config, audit log, reports, history
$APP_DIR     = Join-Path $env:APPDATA "ADSvcAcctMgr"

# Append-only CSV audit log; every action is recorded here
$AUDIT_LOG   = Join-Path $APP_DIR "audit_log.csv"

# SHA-256 hash of the audit log — used to detect tampering
$AUDIT_HASH  = Join-Path $APP_DIR "audit_log.sha256"

# Directory for HTML inventory/audit reports
$REPORT_DIR  = Join-Path $APP_DIR "reports"

# JSON snapshot of discovered accounts — used by drift detection
$BASELINE_FILE = Join-Path $APP_DIR "baseline.json"

# Archived baseline snapshots (one per Save-Baseline call)
$HISTORY_DIR = Join-Path $APP_DIR "history"

# Persisted user configuration (SMTP, naming patterns, thresholds, etc.)
$CONFIG_FILE = Join-Path $APP_DIR "config.json"

# Ensure all required directories exist before anything else runs
foreach ($dir in @($APP_DIR, $REPORT_DIR, $HISTORY_DIR)) {
    if (-not (Test-Path $dir)) {
        New-Item $dir -ItemType Directory -Force | Out-Null
    }
}

# ── Default configuration object ──────────────────────────────────────────────
# These values are used when no saved config.json exists, or as fallbacks
# for any property missing from an older saved configuration.
$DEFAULT_CFG = [PSCustomObject]@{
    # Regex patterns that identify accounts as service accounts by naming convention.
    # Accounts not matching any pattern trigger a naming-violation warning.
    NamingPatterns     = @("^svc_","^msa_","^gmsa_","^sa_","^svc-","^sa-","^adm_svc","^_svc")

    # SMTP settings for alert emails — password stored as DPAPI-encrypted string
    SmtpServer         = ""
    SmtpPort           = 587
    SmtpFrom           = ""
    SmtpTo             = ""
    SmtpUseSsl         = $true
    SmtpUser           = ""
    SmtpPassEncrypted  = ""   # ConvertFrom-SecureString output — DPAPI, user/machine bound
    SmtpTimeoutSec     = 30   # Per-attempt timeout in seconds
    SmtpRetryCount     = 2    # Total attempts before giving up

    # Accounts with no logon for this many days are flagged as stale
    StaleThresholdDays = 90

    # Warn when password expires within this many days
    PwdWarnDays        = 14

    # Health audit flags passwords not changed within this many days
    PwdMaxAgeDays      = 365

    # Rows per page in the paged display helper
    PageSize           = 30

    # Max LDAP page size for server-side queries (tune for large domains)
    LdapPageSize       = 500

    # Well-known privileged AD groups scanned for service account membership.
    # Membership in these groups is a security finding for service accounts.
    AdminGroups        = @(
        "Domain Admins","Enterprise Admins","Schema Admins","Administrators",
        "Account Operators","Backup Operators","Server Operators",
        "Print Operators","Group Policy Creator Owners"
    )

    # Compliance framework label shown in HTML audit reports
    ComplianceFramework = "CIS"

    # Additional forest FQDNs to include in multi-forest scans
    TrustedForests     = @()
}

# ── Load or initialise configuration ──────────────────────────────────────────
# If a saved config exists, merge it with defaults so any new keys added in a
# later version of the script are automatically available with sensible values.
$CFG = if (Test-Path $CONFIG_FILE) {
    $saved = Get-Content $CONFIG_FILE -Raw | ConvertFrom-Json
    # Merge: add any default key that is absent from the saved config
    foreach ($prop in $DEFAULT_CFG.PSObject.Properties) {
        if (-not ($saved.PSObject.Properties.Name -contains $prop.Name)) {
            $saved | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
        }
    }
    $saved
} else {
    $DEFAULT_CFG
}

# ── Session-level state flags ──────────────────────────────────────────────────
# $script: scope keeps these accessible from nested functions without passing params
$script:WHATIF     = $DryRun.IsPresent    # True when running in preview (dry-run) mode
$script:READONLY   = $ReadOnly.IsPresent  # True when all writes are blocked
$script:ROLE       = "Unknown"            # Resolved role: DomainAdmin | DelegatedAdmin | ReadOnly
$script:AllDomains = @()                  # Cached list of discovered forest domains (hashtable[])

# ══════════════════════════════════════════════════════════════════════════════
#  CONSOLE HELPERS — Consistent, colour-coded output formatting
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS  Prints a major section header with a double-line border.
.PARAMETER T  Header text to display.
.PARAMETER C  Foreground colour (defaults to Cyan).
#>
function Write-Header {
    param([string]$T, [ConsoleColor]$C = 'Cyan')
    $line = "═" * 72
    Write-Host "`n$line`n  $T`n$line" -ForegroundColor $C
}

<#
.SYNOPSIS  Prints a sub-section label with a leading dash separator.
#>
function Write-Sub  { param([string]$T) Write-Host "`n  ── $T" -ForegroundColor DarkCyan }

<#
.SYNOPSIS  Prints a step/action indicator (arrow prefix, yellow).
#>
function Write-Step { param([string]$T) Write-Host "  ► $T" -ForegroundColor Yellow }

<#
.SYNOPSIS  Prints a success confirmation (green tick).
#>
function Write-OK   { param([string]$T) Write-Host "  ✔  $T" -ForegroundColor Green }

<#
.SYNOPSIS  Prints a non-critical warning (yellow triangle).
#>
function Write-Warn { param([string]$T) Write-Host "  ⚠  $T" -ForegroundColor DarkYellow }

<#
.SYNOPSIS  Prints a failure/error message (red cross).
#>
function Write-Fail { param([string]$T) Write-Host "  ✘  $T" -ForegroundColor Red }

<#
.SYNOPSIS  Prints an informational note (grey).
#>
function Write-Info { param([string]$T) Write-Host "  ℹ  $T" -ForegroundColor Gray }

<#
.SYNOPSIS  Prints a critical/magenta alert (used for ACL backdoors, integrity failures).
#>
function Write-Crit { param([string]$T) Write-Host "  ██ $T" -ForegroundColor Magenta }

# ── Input helpers ─────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Strips characters that are illegal in AD SAM Account Names and enforces the
    20-character maximum length mandated by the AD schema.
.DESCRIPTION
    The following characters are removed: / \ [ ] : ; | = , + * ? < > @ " °
    If the result exceeds 20 characters it is truncated and the user is warned.
.PARAMETER InputName  The raw string to sanitise.
.OUTPUTS   [string]   A cleaned SAM Account Name safe for use with New-ADUser etc.
#>
function Get-SanitizedSAM {
    param([string]$InputName)

    # Remove all characters that AD rejects in SAM Account Names
    $clean = ($InputName -replace '[\/\\\[\]:;|=,+*?<>@"°]', '').Trim()

    # AD enforces a hard 20-character limit on sAMAccountName
    if ($clean.Length -gt 20) {
        Write-Warn "SAM name truncated to 20 characters."
        $clean = $clean.Substring(0, 20)
    }
    return $clean
}

<#
.SYNOPSIS  Prompts for input, loops until a non-empty value is entered.
.PARAMETER P  Prompt label.
.PARAMETER D  Default value shown in brackets; accepted by pressing ENTER.
.OUTPUTS   [string]  The user's input or the default value.
#>
function Read-NonEmpty {
    param([string]$P, [string]$D = "")
    do {
        $hint  = if ($D) { " [default: $D]" } else { "" }
        $value = Read-Host "  $P$hint"
        if (-not $value -and $D) { $value = $D }
    } while (-not $value)
    return $value
}

<#
.SYNOPSIS  Prompts for a SAM Account Name, sanitising the result automatically.
.NOTES     Always use this instead of Read-Host when collecting account names.
#>
function Read-SAMName {
    param([string]$P, [string]$D = "")
    return Get-SanitizedSAM (Read-NonEmpty $P $D)
}

<#
.SYNOPSIS
    Displays a numbered menu and returns the index of the chosen item.
.PARAMETER P   Prompt text displayed above the option list.
.PARAMETER O   Array of option strings.
.PARAMETER D   Index of the default option (highlighted with ►).
.PARAMETER C   Colour for the prompt text.
.OUTPUTS  [int]  Zero-based index of the selected option.
#>
function Read-Choice {
    param([string]$P, [string[]]$O, [int]$D = 0, [ConsoleColor]$C = 'White')
    Write-Host "`n  $P" -ForegroundColor $C
    for ($i = 0; $i -lt $O.Count; $i++) {
        $marker = if ($i -eq $D) { "►" } else { " " }
        Write-Host ("   [{0}] {1} {2}" -f $i, $marker, $O[$i])
    }
    do {
        $raw = Read-Host "  Choice (default $D)"
        if ($raw -eq "") { return $D }
        $n = 0
    } while (-not [int]::TryParse($raw, [ref]$n) -or $n -lt 0 -or $n -ge $O.Count)
    return $n
}

<#
.SYNOPSIS  Asks a Y/N confirmation question and returns $true for Yes.
#>
function Confirm-Action {
    param([string]$M = "Proceed?")
    return ((Read-Host "`n  $M [Y/N]") -match "^[Yy]")
}

<#
.SYNOPSIS  Pauses console output until the user presses ENTER.
#>
function Pause-Screen {
    Write-Host "`n  Press ENTER to continue..." -ForegroundColor DarkGray
    $null = Read-Host
}

<#
.SYNOPSIS
    Null-coalescing helper — returns $Value when it is non-null and non-empty,
    otherwise returns $Default.
.DESCRIPTION
    PowerShell 5.1 does not support the ?? operator (added in PS 7.0).
    This function provides equivalent behaviour compatible with PS 5.1+.
.PARAMETER Value    The value to test.
.PARAMETER Default  Fallback value returned when $Value is null or empty.
#>
function Get-Coalesce {
    param($Value, $Default = "")
    if ($null -ne $Value -and "$Value" -ne '') { return $Value }
    return $Default
}

<#
.SYNOPSIS
    Guards write operations.
    Returns $false and prints an error when the session is in read-only mode.
.OUTPUTS  [bool]  $true if writes are permitted; $false otherwise.
#>
function Assert-WriteAllowed {
    if ($script:READONLY) {
        Write-Fail "Session is READ-ONLY. No AD changes are permitted."
        return $false
    }
    return $true
}

<#
.SYNOPSIS
    Wraps a write operation in WhatIf (dry-run) or execute mode.
.DESCRIPTION
    When $script:WHATIF is true, the action is logged as WHATIF and the script block
    is NOT executed — zero changes are made to AD.
    When $script:WHATIF is false, the script block runs inside a try/catch that logs
    failures to the audit log and re-throws on error.
.PARAMETER Action  Label for the audit log entry (e.g. "CREATE_gMSA").
.PARAMETER Target  The SAM Account Name or object being acted upon.
.PARAMETER Block   The PowerShell script block that performs the actual AD change.
#>
function Invoke-WhatIf {
    param([string]$Action, [string]$Target, [scriptblock]$Block)

    if ($script:WHATIF) {
        # Dry-run: announce what would happen and log it, then stop
        Write-Host "  [WHATIF] Would execute: $Action on '$Target'" -ForegroundColor Magenta
        Write-AuditLog $Action $Target "WHATIF" "DryRun=true"
        return
    }
    try {
        & $Block
    }
    catch {
        Write-Fail "[$Action] on '$Target' failed: $($_.Exception.Message)"
        Write-AuditLog $Action $Target "FAILURE" $_.Exception.Message
        throw  # Re-throw so the caller can handle or display the error
    }
}

<#
.SYNOPSIS
    Displays a collection of objects in pages, allowing navigation forward/back.
.DESCRIPTION
    Prevents large result sets from flooding the console by slicing them into
    pages of $PS rows. The user can type N (next), P (previous), or Q/ENTER (quit).
.PARAMETER Data   The array of objects to display.
.PARAMETER Props  Optional list of property names for Format-Table column selection.
.PARAMETER PS     Page size override; defaults to $CFG.PageSize.
#>
function Show-Paged {
    param([object[]]$Data, [string[]]$Props = @(), [int]$PS = 0)
    if ($PS -eq 0) { $PS = $CFG.PageSize }
    if (-not $Data -or $Data.Count -eq 0) { Write-Info "No data to display."; return }

    $total = $Data.Count
    $pages = [Math]::Ceiling($total / $PS)
    $page  = 0

    do {
        # Slice the current page out of the full result set
        $slice = $Data | Select-Object -Skip ($page * $PS) -First $PS
        if ($Props) { $slice | Format-Table $Props -AutoSize -Wrap }
        else        { $slice | Format-Table -AutoSize -Wrap }

        Write-Host ("`n  Page {0}/{1}  ({2} total)  [N]ext [P]rev [Q]uit" -f ($page + 1), $pages, $total) -ForegroundColor DarkGray
        if ($pages -le 1) { break }  # Single page: no navigation needed

        $nav = Read-Host ""
        if    ($nav -match "^[Nn]" -and $page -lt $pages - 1) { $page++ }
        elseif($nav -match "^[Pp]" -and $page -gt 0)          { $page-- }
        else  { break }
    } while ($true)
}

# ══════════════════════════════════════════════════════════════════════════════
#  SMTP — Alert email delivery with DPAPI-secured password and retry logic
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Decrypts the DPAPI-protected SMTP password stored in config.
.DESCRIPTION
    The password is stored via ConvertFrom-SecureString (DPAPI, user + machine bound).
    Returns a plain-text string for use with NetworkCredential, or $null if no
    password is configured or decryption fails.
.OUTPUTS  [string] or $null
.NOTES
    DPAPI encryption is tied to the Windows user account and machine. The password
    cannot be decrypted by another user account or on a different machine.
#>
function Get-SmtpPassword {
    if (-not $CFG.SmtpPassEncrypted) { return $null }
    try {
        $ss  = $CFG.SmtpPassEncrypted | ConvertTo-SecureString
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
    }
    catch { return $null }
}

<#
.SYNOPSIS
    Sends an HTML-formatted alert email using the configured SMTP settings.
.DESCRIPTION
    Attempts delivery up to $CFG.SmtpRetryCount times with a 5-second pause
    between attempts. Uses SSL if configured. Logs success or failure to audit log.
.PARAMETER Subject  Email subject line.
.PARAMETER Body     HTML body content.
.NOTES    SMTP must be configured via Settings → Configure SMTP before this works.
#>
function Send-AlertEmail {
    param([string]$Subject, [string]$Body)

    # Abort early if SMTP is not configured
    if (-not $CFG.SmtpServer -or -not $CFG.SmtpTo) {
        Write-Warn "SMTP not configured. Use Settings → Configure SMTP to enable email alerts."
        return
    }

    $maxAttempts = [Math]::Max(1, $CFG.SmtpRetryCount)

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            # Build the SMTP client with timeout (milliseconds) and SSL flag
            $smtp            = [System.Net.Mail.SmtpClient]::new($CFG.SmtpServer, $CFG.SmtpPort)
            $smtp.EnableSsl  = $CFG.SmtpUseSsl
            $smtp.Timeout    = $CFG.SmtpTimeoutSec * 1000  # Convert seconds to milliseconds

            # Add credentials only when a username is configured
            if ($CFG.SmtpUser) {
                $smtp.Credentials = [System.Net.NetworkCredential]::new($CFG.SmtpUser, (Get-SmtpPassword))
            }

            # Compose the HTML message
            $msg            = [System.Net.Mail.MailMessage]::new($CFG.SmtpFrom, $CFG.SmtpTo, $Subject, $Body)
            $msg.IsBodyHtml = $true

            $smtp.Send($msg)
            Write-OK "Alert email sent to $($CFG.SmtpTo)."
            Write-AuditLog "EMAIL_ALERT" $CFG.SmtpTo "SUCCESS" "Subject=$Subject"
            return  # Success — exit retry loop
        }
        catch {
            Write-Warn "SMTP attempt $attempt/$maxAttempts failed: $($_.Exception.Message)"
            if ($attempt -lt $maxAttempts) {
                Start-Sleep -Seconds 5  # Wait before retrying
            }
            else {
                Write-Fail "All SMTP delivery attempts failed."
                Write-AuditLog "EMAIL_ALERT" $CFG.SmtpTo "FAILURE" $_.Exception.Message
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT ENGINE — Tamper-evident audit log with SHA-256 integrity hashing
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Appends a structured entry to the CSV audit log and updates its SHA-256 hash.
.DESCRIPTION
    Every create, modify, delete, test, and security operation calls this function.
    The log records who did what, to which account, with what outcome, and when.
    After each write the SHA-256 hash of the entire log file is recomputed and
    stored in a companion .sha256 file for integrity verification.
.PARAMETER Action   Short identifier for the operation (e.g. "CREATE", "DELETE").
.PARAMETER Target   The SAM Account Name or object affected.
.PARAMETER Result   Outcome string: SUCCESS | FAILURE | INFO | WHATIF.
.PARAMETER Details  Optional free-text context (error messages, parameter values, etc.).
.NOTES
    The hash file only proves the log has not changed since the last write from
    THIS script. For a fully tamper-proof audit trail, forward logs to a SIEM.
#>
function Write-AuditLog {
    param([string]$Action, [string]$Target, [string]$Result, [string]$Details = "")

    # Build the structured log entry
    $entry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Operator  = "$env:USERDOMAIN\$env:USERNAME"
        Hostname  = $env:COMPUTERNAME
        Action    = $Action
        Target    = $Target
        Result    = $Result
        Details   = $Details
    }

    # Format as a CSV row — quote every field to handle commas in values
    $line       = '"' + ($entry.PSObject.Properties.Value -join '","') + '"'
    $needHeader = (-not (Test-Path $AUDIT_LOG)) -or (Get-Item $AUDIT_LOG -EA SilentlyContinue).Length -eq 0

    try {
        # Write header row only when creating a new log file
        if ($needHeader) {
            '"Timestamp","Operator","Hostname","Action","Target","Result","Details"' |
                Set-Content $AUDIT_LOG -Encoding UTF8
        }

        # Append the data row
        $line | Add-Content $AUDIT_LOG -Encoding UTF8

        # Recompute and store the SHA-256 hash for integrity verification
        (Get-FileHash $AUDIT_LOG -Algorithm SHA256).Hash |
            Set-Content $AUDIT_HASH -Encoding UTF8
    }
    catch {
        # Log failures are non-fatal — display a warning but continue
        Write-Warn "Audit log write failed: $($_.Exception.Message)"
    }

    # Echo the entry to the console with result-appropriate colour
    $colour = switch ($Result) {
        "SUCCESS" { "Green" }
        "FAILURE" { "Red" }
        "WHATIF"  { "Magenta" }
        default   { "Gray" }
    }
    Write-Host ("  [AUDIT] {0} → {1} ({2})" -f $Action, $Target, $Result) -ForegroundColor $colour
}

<#
.SYNOPSIS
    Verifies that the audit log has not been tampered with since the last write.
.DESCRIPTION
    Recomputes the SHA-256 hash of the audit log and compares it to the stored
    companion hash. A mismatch indicates the log was modified outside of this script.
.NOTES
    Run this before exporting the log for compliance review to confirm chain of custody.
#>
function Test-AuditLogIntegrity {
    if (-not (Test-Path $AUDIT_LOG))  { Write-Info "No audit log found. Nothing to verify."; return }
    if (-not (Test-Path $AUDIT_HASH)) { Write-Warn "No integrity hash file found — log integrity unverified."; return }

    $storedHash  = (Get-Content $AUDIT_HASH -Raw).Trim()
    $currentHash = (Get-FileHash $AUDIT_LOG -Algorithm SHA256).Hash

    if ($storedHash -eq $currentHash) {
        Write-OK "Audit log integrity VERIFIED — SHA-256 hash matches."
    }
    else {
        Write-Fail "INTEGRITY FAILURE — SHA-256 hash mismatch! The audit log may have been tampered with."
        Write-Fail "Stored : $storedHash"
        Write-Fail "Current: $currentHash"
        Write-AuditLog "INTEGRITY_FAILURE" $AUDIT_LOG "FAILURE" "HashMismatch"
    }
}

<#
.SYNOPSIS  Exports the audit log to a JSON file suitable for SIEM ingestion.
.PARAMETER F  Full file path for the output JSON file.
#>
function Export-SIEMJson {
    param([string]$F)
    if (Test-Path $AUDIT_LOG) {
        Import-Csv $AUDIT_LOG | ConvertTo-Json -Depth 5 | Set-Content $F -Encoding UTF8
        Write-OK "SIEM JSON exported: $F"
    }
}

<#
.SYNOPSIS  Exports the audit log in Common Event Format (CEF) for Splunk/QRadar.
.PARAMETER F  Full file path for the output CEF file.
.NOTES    CEF severity: 3=LOW (success), 7=HIGH (failure).
#>
function Export-SIEMCef {
    param([string]$F)
    if (Test-Path $AUDIT_LOG) {
        Import-Csv $AUDIT_LOG | ForEach-Object {
            $severity = switch ($_.Result) { "SUCCESS" { "3" } "FAILURE" { "7" } default { "1" } }
            "CEF:0|ADSvcAcctMgr|$SCRIPT_VERSION|$($_.Action)|$($_.Action)|$severity|" +
            "suser=$($_.Operator) dhost=$($_.Hostname) duser=$($_.Target) " +
            "msg=$($_.Details) rt=$($_.Timestamp)"
        } | Set-Content $F -Encoding UTF8
        Write-OK "SIEM CEF exported: $F"
    }
}

<#
.SYNOPSIS  Exports the audit log in RFC-3164 Syslog format.
.PARAMETER F  Full file path for the output Syslog file.
.NOTES    Priority: 11=FAILURE (user.warning), 6=SUCCESS (user.info), 5=other (user.notice).
#>
function Export-SIEMSyslog {
    param([string]$F)
    if (Test-Path $AUDIT_LOG) {
        Import-Csv $AUDIT_LOG | ForEach-Object {
            $priority  = switch ($_.Result) { "FAILURE" { "11" } "SUCCESS" { "6" } default { "5" } }
            $timestamp = [datetime]::Parse($_.Timestamp).ToString("MMM dd HH:mm:ss")
            "<$priority>$timestamp $env:COMPUTERNAME ADSvcAcctMgr: " +
            "Action=$($_.Action) Target=$($_.Target) Result=$($_.Result) " +
            "Op=$($_.Operator) Details=$($_.Details)"
        } | Set-Content $F -Encoding UTF8
        Write-OK "SIEM Syslog exported: $F"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  ROLE & SESSION SETUP — Determine operator privileges at startup
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Detects the current operator's effective AD privileges.
.DESCRIPTION
    Checks Domain Admins membership first (full rights), then local Administrators
    (delegated), falling back to ReadOnly if neither is found or an error occurs.
.OUTPUTS  [string]  "DomainAdmin" | "DelegatedAdmin" | "ReadOnly"
#>
function Get-SessionRole {
    try {
        # Check if the current user is a (direct or nested) member of Domain Admins
        $isDomAdmin = Get-ADGroupMember "Domain Admins" -Recursive -EA SilentlyContinue |
                      Where-Object { $_.SamAccountName -eq $env:USERNAME }
        if ($isDomAdmin) { return "DomainAdmin" }

        # Check local Administrators token group for delegated admin scenarios
        $identity    = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $isLocalAdmin = $identity.Groups | Where-Object {
            try { ($_.Translate([System.Security.Principal.NTAccount])).Value -match "Administrators" }
            catch { $false }
        }
        return if ($isLocalAdmin) { "DelegatedAdmin" } else { "ReadOnly" }
    }
    catch { return "ReadOnly" }
}

<#
.SYNOPSIS
    Runs at startup: detects role, applies -ReadOnly/-DryRun flags, and prompts
    the operator to confirm their session mode.
.DESCRIPTION
    Operators can always choose to downgrade to read-only even when they have
    write permissions. A DryRun session allows them to preview all operations
    without committing any changes to Active Directory.
#>
function Invoke-RoleSetup {
    $detected = Get-SessionRole
    Write-Info "Detected role: $detected"

    if ($script:READONLY -or $detected -eq "ReadOnly") {
        # Force read-only when the -ReadOnly switch was passed or no write rights detected
        $script:READONLY = $true
        $script:ROLE     = "ReadOnly"
        Write-Warn "READ-ONLY session — no AD changes will be made in this session."
    }
    else {
        # Let the operator choose their access level for this session
        $choice = Read-Choice "Session mode:" @(
            "Full access  (create / modify / delete)",
            "Read-only    (view / audit / report only)"
        ) 0
        $script:READONLY = ($choice -eq 1)
        $script:ROLE     = if ($script:READONLY) { "ReadOnly" } else { $detected }
    }

    if ($script:WHATIF) {
        Write-Warn "DRY-RUN active — all write operations will be previewed but NOT committed."
    }

    Write-AuditLog "SESSION_START" "SYSTEM" "INFO" `
        "Role=$($script:ROLE) WhatIf=$($script:WHATIF) Mode=$Mode"
}

# ══════════════════════════════════════════════════════════════════════════════
#  AD HELPERS — Reusable Active Directory utility functions
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Returns a hashtable of key domain properties for a given FQDN (or current domain).
.PARAMETER TargetDomain  Domain FQDN. Empty string = current domain.
.OUTPUTS   [hashtable]  Keys: FQDN, DN, NetBIOS, PDC
#>
function Get-DomainInfo {
    param([string]$TargetDomain = "")
    $params = @{}
    if ($TargetDomain) { $params.Identity = $TargetDomain }
    $dom = Get-ADDomain @params
    return @{
        FQDN    = $dom.DNSRoot
        DN      = $dom.DistinguishedName
        NetBIOS = $dom.NetBIOSName
        PDC     = $dom.PDCEmulator
    }
}

<#
.SYNOPSIS
    Enumerates all domains in the current (and optionally trusted) forests.
.PARAMETER RootDomain  Optional root forest domain FQDN. Empty = current forest.
.OUTPUTS   [hashtable[]]  Array of domain info hashtables (FQDN, DN, NetBIOS, PDC).
.NOTES     Trusted forests are read from $CFG.TrustedForests.
#>
function Get-ForestDomains {
    param([string]$RootDomain = "")
    $domains = @()

    try {
        $forestParams = @{}
        if ($RootDomain) { $forestParams.Identity = $RootDomain }
        $forest = Get-ADForest @forestParams

        # Resolve each domain in the primary forest
        $domains += $forest.Domains | ForEach-Object {
            try { Get-DomainInfo $_ } catch { Write-Warn "Cannot reach domain '$_'." }
        }

        # Extend to configured trusted forests
        foreach ($trustedForest in $CFG.TrustedForests) {
            try {
                $tf2 = Get-ADForest -Identity $trustedForest -EA Stop
                $domains += $tf2.Domains | ForEach-Object {
                    try { Get-DomainInfo $_ } catch {}
                }
            }
            catch { Write-Warn "Cannot reach trusted forest: $trustedForest" }
        }
    }
    catch { Write-Fail "Forest enumeration failed: $($_.Exception.Message)" }

    return $domains
}

<#
.SYNOPSIS  Returns $true when the supplied OU Distinguished Name exists in AD.
.PARAMETER OU  OU Distinguished Name to validate (e.g. "OU=ServiceAccounts,DC=corp,DC=com").
#>
function Get-ValidatedOU {
    param([string]$OU)
    try { Get-ADOrganizationalUnit -Identity $OU -EA Stop | Out-Null; return $true }
    catch { return $false }
}

<#
.SYNOPSIS
    Resolves what type of AD account a given SAM Account Name represents.
.DESCRIPTION
    Tries Get-ADUser first, then Get-ADServiceAccount.
    Distinguishes MSA (msDS-ManagedServiceAccount) from gMSA (msDS-GroupManagedServiceAccount).
.PARAMETER Sam     The sAMAccountName to resolve.
.PARAMETER Server  Optional DC name to query (defaults to PDC).
.OUTPUTS   [string] or $null  "Standard" | "MSA" | "gMSA" | $null (not found)
#>
function Resolve-AccountType {
    param([string]$Sam, [string]$Server = "")
    $serverParam = @{}
    if ($Server) { $serverParam.Server = $Server }

    try { Get-ADUser $Sam -EA Stop @serverParam | Out-Null; return "Standard" } catch {}
    try {
        $sa = Get-ADServiceAccount $Sam -Properties ObjectClass -EA Stop @serverParam
        return if ($sa.ObjectClass -eq "msDS-GroupManagedServiceAccount") { "gMSA" } else { "MSA" }
    }
    catch {}
    return $null  # Account not found in this domain
}

<#
.SYNOPSIS
    Generates a cryptographically random password of the specified length.
.DESCRIPTION
    Uses System.Security.Cryptography.RandomNumberGenerator (CSPRNG) to ensure
    each character is drawn from a uniform distribution across the character set.
    The character set includes upper, lower, digits, and common symbols.
.PARAMETER Len  Desired password length. Defaults to 24 characters.
.OUTPUTS   [System.Security.SecureString]  A SecureString holding the generated password.
.NOTES
    Use Get-PlainText to convert to plain text only when absolutely necessary
    (e.g., credential export). Never log plain-text passwords.
#>
function New-SecurePassword {
    param([int]$Len = 24)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+'
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new($Len)
    $rng.GetBytes($bytes)

    # Map each byte to a character index using modulo — uniform only when char set
    # size is a power-of-2 divisor of 256; for non-powers-of-2 there is slight bias.
    # For service account passwords this is an acceptable trade-off.
    $plain = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    return ConvertTo-SecureString $plain -AsPlainText -Force
}

<#
.SYNOPSIS  Converts a SecureString to a plain-text string for display or export.
.NOTES     Only call this at the very last moment before output. Never log the result.
#>
function Get-PlainText {
    param([System.Security.SecureString]$SS)
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SS)
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
}

<#
.SYNOPSIS
    Returns the resultant Password Settings Object (PSO/Fine-Grained Policy) for an account.
.DESCRIPTION
    A PSO overrides the default domain password policy for the specified account.
    Returns $null if no PSO is applied (domain default is in effect).
.PARAMETER Sam  SAM Account Name to check.
.OUTPUTS  PSO object or $null
#>
function Get-AccountPSO {
    param([string]$Sam)
    try   { return Get-ADUserResultantPasswordPolicy -Identity $Sam -EA Stop }
    catch { return $null }  # No PSO, or insufficient rights — both return null
}

<#
.SYNOPSIS  Tests whether a SAM Account Name matches any configured naming convention pattern.
.PARAMETER Sam  The sAMAccountName to test.
.OUTPUTS   [bool]  $true if at least one pattern matches.
#>
function Test-NamingConvention {
    param([string]$Sam)
    foreach ($pattern in $CFG.NamingPatterns) {
        if ($Sam -match $pattern) { return $true }
    }
    return $false
}

<#
.SYNOPSIS  Persists the current $CFG object to config.json and logs the operation.
#>
function Save-Config {
    $CFG | ConvertTo-Json -Depth 5 | Set-Content $CONFIG_FILE -Encoding UTF8
    Write-OK "Configuration saved to $CONFIG_FILE."
    Write-AuditLog "SETTINGS_SAVE" "SYSTEM" "SUCCESS" ""
}

# ══════════════════════════════════════════════════════════════════════════════
#  CREATE MODULE — Account creation: wizard, clone, and bulk CSV
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS  Entry point for the Create submenu.
.PARAMETER Dom  Domain info hashtable from Get-DomainInfo.
#>
function Invoke-CreateMenu {
    param([hashtable]$Dom)

    if (-not (Assert-WriteAllowed)) { Pause-Screen; return }

    Write-Header "CREATE SERVICE ACCOUNT"
    $choice = Read-Choice "Choose creation method:" @(
        "Single account wizard",
        "Clone an existing account",
        "Bulk import from CSV file",
        "Generate CSV bulk-import template"
    )

    switch ($choice) {
        0 { New-SingleAccount $Dom }
        1 { New-ClonedAccount $Dom }
        2 { New-BulkFromCSV  $Dom }
        3 {
            # Write a template CSV to the Desktop with one example of each account type
            $templatePath = Join-Path ([Environment]::GetFolderPath("Desktop")) "SvcAcct_BulkTemplate.csv"
            @"
Type,SamName,DisplayName,Description,OU,Department,Owner,PwdNeverExpires,BindHost,AllowedPrincipals,PwdInterval,KerberosEncryption
Standard,svc_myapp,MyApp Service,Service account for MyApp,"OU=ServiceAccounts,DC=domain,DC=com",IT,jsmith,true,,,,
MSA,msa_webapp,WebApp MSA,MSA for WebApp,"OU=ServiceAccounts,DC=domain,DC=com",,,,WEBSERVER01,,,
gMSA,gmsa_api,API gMSA,gMSA for API Cluster,"OU=ServiceAccounts,DC=domain,DC=com",,,,,"SG_APIFarm,APINODE01`$",30,AES256
"@ | Set-Content $templatePath -Encoding UTF8
            Write-OK "Template saved to: $templatePath"
            Write-Info "Edit the template and use 'Bulk import from CSV' to create all accounts at once."
        }
    }
    Pause-Screen
}

<#
.SYNOPSIS
    Interactive wizard to create a single Standard, MSA, or gMSA service account.
.DESCRIPTION
    Walks the operator through account type selection, naming validation, OU selection,
    type-specific configuration (password policy, SPN, KDS key, delegation principals),
    confirmation, and optional post-creation tasks (group assignments, SPNs).
    Credential export (Standard accounts) is offered after creation.
.PARAMETER Dom  Domain info hashtable.
.NOTES
    gMSA creation requires a KDS Root Key in the domain.
    MSA creation requires Windows Server 2008 R2 or later Domain Functional Level.
#>
function New-SingleAccount {
    param([hashtable]$Dom)

    # ── Step 1: Select account type ───────────────────────────────────────────
    $typeIndex = Read-Choice "Account type:" @(
        "Standard  (svc_* user account, password managed manually)",
        "MSA       (single-host, password managed automatically by AD)",
        "gMSA      (multi-host cluster, password managed automatically by AD)"
    )
    $type   = @("Standard", "MSA", "gMSA")[$typeIndex]
    $prefix = @{ Standard = "svc_"; MSA = "msa_"; gMSA = "gmsa_" }[$type]

    # ── Step 2: Identity ──────────────────────────────────────────────────────
    Write-Sub "Identity"
    $sam = Read-SAMName "SAM Account Name" "${prefix}myapp"

    # Warn if the name does not follow the configured naming convention
    if (-not (Test-NamingConvention $sam)) {
        Write-Warn "'$sam' does not match any configured naming pattern:"
        $CFG.NamingPatterns | ForEach-Object { Write-Warn "  $_ " }
        if (-not (Confirm-Action "Continue with this non-standard name?")) { return }
    }

    # Refuse to create a duplicate
    if (Resolve-AccountType $sam) {
        Write-Fail "'$sam' already exists in Active Directory."
        Write-AuditLog "CREATE" $sam "FAILURE" "AlreadyExists"
        return
    }

    $displayName = Read-NonEmpty "Display Name"  "$sam Service Account"
    $description = Read-NonEmpty "Description"   "Service account for $sam"

    # ── Step 3: Target OU ─────────────────────────────────────────────────────
    Write-Sub "Target Organisational Unit"
    do {
        $ou = Read-NonEmpty "Target OU (Distinguished Name)" "OU=ServiceAccounts,$($Dom.DN)"
        if (Get-ValidatedOU $ou) { break }
        Write-Fail "OU not found in AD. Please re-enter."
    } while ($true)

    # ── Step 4: Type-specific configuration ───────────────────────────────────
    $cfg = @{
        Sam  = $sam; Disp = $displayName; Desc = $description
        OU   = $ou;  Domain = $Dom.FQDN;  Type = $type
    }

    switch ($type) {
        "Standard" {
            # Password expiry: never-expires is typical for service accounts but
            # may conflict with company security policy — capture operator intent
            $cfg.PwdNeverExpires = (Read-Choice "Password expiry:" @(
                "Never expires (recommended for service accounts)",
                "Follow domain / PSO policy"
            ) 0) -eq 0

            $cfg.PwdLen = [int](Read-NonEmpty "Password length (characters)" "24")
            $cfg.Dept   = Read-Host "  Department (ENTER to skip)"
            $cfg.Owner  = Read-Host "  Owner SAM Account Name (ENTER to skip)"
        }
        "MSA" {
            Write-Warn "MSA requires Windows Server 2008 R2 or later Domain Functional Level."
            $cfg.BindHost = Read-Host "  Computer account to bind MSA to (ENTER to skip)"
        }
        "gMSA" {
            # gMSA requires a KDS Root Key — assert/create it now
            Assert-KDSRootKey $Dom

            $cfg.PwdInterval = [int](Read-NonEmpty "Password rotation interval (days)" "30")

            $raw             = Read-NonEmpty "Principals allowed to retrieve password (comma-separated)"
            $cfg.Principals  = $raw -split "\s*,\s*" | Where-Object { $_ }

            $encIndex    = Read-Choice "Kerberos encryption type:" @(
                "AES256 (recommended)", "AES128", "RC4 (legacy, avoid)", "Domain default"
            ) 0
            $cfg.KerbEnc = @("AES256", "AES128", "RC4", $null)[$encIndex]
        }
    }

    # ── Step 5: Confirmation ──────────────────────────────────────────────────
    Write-Header "CONFIRM ACCOUNT CREATION" Yellow
    $cfg.GetEnumerator() | Sort-Object Name | ForEach-Object {
        Write-Host ("  {0,-22}: {1}" -f $_.Key, ($_.Value -join ", ")) -ForegroundColor White
    }
    if ($script:WHATIF) { Write-Warn "DRY-RUN active — no AD changes will be committed." }
    if (-not (Confirm-Action "CREATE this account?")) {
        Write-AuditLog "CREATE" $sam "INFO" "CancelledByOperator"
        return
    }

    # ── Step 6: Create in AD ──────────────────────────────────────────────────
    $createdOK = $false
    try {
        Invoke-WhatIf "CREATE_$type" $sam {
            switch ($type) {
                "Standard" {
                    $securePassword = New-SecurePassword -Len $cfg.PwdLen
                    $params = @{
                        Name                  = $cfg.Sam
                        SamAccountName        = $cfg.Sam
                        UserPrincipalName     = "$($cfg.Sam)@$($cfg.Domain)"
                        DisplayName           = $cfg.Disp
                        Description           = $cfg.Desc
                        Path                  = $cfg.OU
                        AccountPassword       = $securePassword
                        PasswordNeverExpires  = $cfg.PwdNeverExpires
                        CannotChangePassword  = $true   # Service accounts should not self-rotate
                        Enabled               = $true
                    }
                    if ($cfg.Dept) { $params.Department = $cfg.Dept }
                    if ($cfg.Owner) {
                        try   { $params.ManagedBy = (Get-ADUser $cfg.Owner -EA Stop).DistinguishedName }
                        catch { Write-Warn "Owner '$($cfg.Owner)' not found in AD — skipped." }
                    }

                    New-ADUser @params | Out-Null

                    # Report whether a PSO (Fine-Grained Password Policy) is in effect
                    $pso = Get-AccountPSO $cfg.Sam
                    if ($pso) {
                        Write-Warn "PSO '$($pso.Name)' applies — MaxPwdAge: $($pso.MaxPasswordAge)"
                    }
                    else { Write-Info "No PSO — domain default password policy applies." }

                    # Offer credential export — operator should transfer to a vault immediately
                    if (Confirm-Action "Export credentials to Desktop text file?") {
                        $credFile = Join-Path ([Environment]::GetFolderPath("Desktop")) "$($cfg.Sam)_creds.txt"
                        @"
SERVICE ACCOUNT CREDENTIALS — STORE IN VAULT, THEN DELETE THIS FILE
============================================================
Account  : $($cfg.Sam)
UPN      : $($cfg.Sam)@$($cfg.Domain)
OU       : $($cfg.OU)
Password : $(Get-PlainText $securePassword)
Created  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Operator : $env:USERDOMAIN\$env:USERNAME
============================================================
"@ | Set-Content $credFile -Encoding UTF8
                        Write-Warn "Credentials saved to: $credFile"
                        Write-Warn "▶ Copy this file to your vault NOW, then delete it from the Desktop."
                        Write-AuditLog "CRED_EXPORT" $cfg.Sam "INFO" "File=$credFile"
                    }
                }

                "MSA" {
                    New-ADServiceAccount `
                        -Name $cfg.Sam -SamAccountName $cfg.Sam `
                        -Description $cfg.Desc -Path $cfg.OU -Enabled $true | Out-Null

                    if ($cfg.BindHost) {
                        # Associate the MSA with its host computer account
                        Add-ADComputerServiceAccount -Identity $cfg.BindHost -ServiceAccount $cfg.Sam
                        Write-OK "MSA bound to host '$($cfg.BindHost)'."
                    }
                }

                "gMSA" {
                    $params = @{
                        Name                                   = $cfg.Sam
                        SamAccountName                         = $cfg.Sam
                        Description                            = $cfg.Desc
                        Path                                   = $cfg.OU
                        DNSHostName                            = "$($cfg.Sam).$($cfg.Domain)"
                        ManagedPasswordIntervalInDays          = $cfg.PwdInterval
                        PrincipalsAllowedToRetrieveManagedPassword = $cfg.Principals
                        Enabled                                = $true
                    }
                    if ($cfg.KerbEnc) { $params.KerberosEncryptionType = $cfg.KerbEnc }
                    New-ADServiceAccount @params | Out-Null
                }
            }
        }
        $createdOK = $true
        Write-AuditLog "CREATE" $sam "SUCCESS" "Type=$type OU=$ou"
        Write-OK "Account '$sam' created successfully!"
    }
    catch {
        Write-Fail "Account creation failed: $($_.Exception.Message)"
        Write-AuditLog "CREATE" $sam "FAILURE" $_.Exception.Message
        return
    }

    # ── Step 7: Optional post-creation tasks ──────────────────────────────────
    if ($createdOK) {
        if (Confirm-Action "Add account to AD groups?") {
            Invoke-GroupAssignment $sam $type
        }
        if ($type -eq "Standard" -and (Confirm-Action "Register Service Principal Names (SPNs)?")) {
            Invoke-SPNManagement $sam "add"
        }
    }
}

<#
.SYNOPSIS
    Clones an existing service account — copies attributes, OU, and group memberships.
.DESCRIPTION
    For Standard accounts: copies Description, Department, ManagedBy, PasswordNeverExpires,
    and group memberships to the new account. A new random password is generated.
    For MSA/gMSA: copies Description and OU only (managed password cannot be cloned).
.PARAMETER Dom  Domain info hashtable.
#>
function New-ClonedAccount {
    param([hashtable]$Dom)

    $sourceSam  = Read-SAMName "Source account SAM name to clone from"
    $sourceType = Resolve-AccountType $sourceSam
    if (-not $sourceType) { Write-Fail "Source account '$sourceSam' not found in AD."; return }

    $newSam = Read-SAMName "New SAM Account Name"
    if (Resolve-AccountType $newSam) { Write-Fail "'$newSam' already exists in AD."; return }

    try {
        if ($sourceType -eq "Standard") {
            $source = Get-ADUser $sourceSam -Properties `
                Description, Department, ManagedBy, PasswordNeverExpires, MemberOf, DistinguishedName

            # Default the target OU to the same OU as the source account
            $defaultOU = $source.DistinguishedName -replace '^CN=[^,]+,', ''
            $targetOU  = Read-NonEmpty "Target OU (DN)" $defaultOU

            Invoke-WhatIf "CLONE_CREATE" $newSam {
                $sp = New-SecurePassword
                New-ADUser `
                    -Name $newSam -SamAccountName $newSam `
                    -UserPrincipalName "$newSam@$($Dom.FQDN)" `
                    -DisplayName "$newSam Service Account" `
                    -Description $source.Description `
                    -Department  $source.Department `
                    -Path        $targetOU `
                    -AccountPassword     $sp `
                    -PasswordNeverExpires $source.PasswordNeverExpires `
                    -CannotChangePassword $true `
                    -Enabled $true | Out-Null

                # Replicate group memberships from source to new account
                foreach ($groupDN in $source.MemberOf) {
                    try {
                        Add-ADGroupMember -Identity $groupDN -Members $newSam
                        Write-OK "  Added to: $($groupDN -replace '^CN=([^,]+).*','$1')"
                    }
                    catch { Write-Warn "  Could not add to group: $groupDN" }
                }

                Write-OK "Cloned '$sourceSam' → '$newSam'."
                Write-OK "Generated password: $(Get-PlainText $sp)"
                Write-Warn "Copy this password to your vault immediately — it will not be shown again."
                Write-AuditLog "CLONE" $newSam "SUCCESS" "Source=$sourceSam"
            }
        }
        else {
            # MSA/gMSA clone: only Description and OU can be carried over
            $source = Get-ADServiceAccount $sourceSam -Properties Description, DistinguishedName
            $targetOU = Read-NonEmpty "Target OU (DN)" ($source.DistinguishedName -replace '^CN=[^,]+,', '')
            Invoke-WhatIf "CLONE_CREATE" $newSam {
                New-ADServiceAccount `
                    -Name $newSam -SamAccountName $newSam `
                    -Description $source.Description -Path $targetOU -Enabled $true | Out-Null
                Write-OK "Cloned '$sourceSam' → '$newSam'."
                Write-AuditLog "CLONE" $newSam "SUCCESS" "Source=$sourceSam Type=$sourceType"
            }
        }
    }
    catch { Write-Fail "Clone failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Creates multiple service accounts from a CSV file in a single operation.
.DESCRIPTION
    Validates all rows before starting, then creates accounts one by one.
    On any failure the operator is offered a full rollback of all accounts
    successfully created in the current batch.
    Required CSV columns: Type, SamName, OU
    Optional columns: DisplayName, Description, PwdNeverExpires, Department, Owner,
                      BindHost (MSA), AllowedPrincipals (gMSA), PwdInterval (gMSA),
                      KerberosEncryption (gMSA)
    Use Invoke-CreateMenu option 3 to generate a template CSV.
.PARAMETER Dom  Domain info hashtable.
#>
function New-BulkFromCSV {
    param([hashtable]$Dom)

    $csvPath = Read-NonEmpty "Full path to CSV file"
    if (-not (Test-Path $csvPath)) { Write-Fail "File not found: $csvPath"; return }

    $rows    = Import-Csv $csvPath
    $required = @("Type", "SamName", "OU")
    $invalid  = @()

    # ── Pre-flight validation: check required columns and naming conventions ──
    foreach ($row in $rows) {
        $missing = $required | Where-Object { -not $row.$_ }
        if ($missing) {
            $invalid += "$($row.SamName) — missing required columns: $($missing -join ', ')"
        }
        if ($row.SamName -and -not (Test-NamingConvention $row.SamName)) {
            $invalid += "$($row.SamName) — naming convention violation"
        }
    }

    if ($invalid) {
        Write-Fail "Validation errors found:"
        $invalid | ForEach-Object { Write-Fail "  · $_" }
        if (-not (Confirm-Action "Continue, skipping the invalid rows?")) { return }
    }

    $ok      = 0
    $failed  = 0
    $skipped = 0
    $created = [System.Collections.Generic.List[string]]::new()  # Track for rollback

    foreach ($row in $rows) {
        $samClean = Get-SanitizedSAM $row.SamName

        # Skip rows that failed pre-flight validation
        $rowIsInvalid = $invalid | Where-Object { $_ -match [regex]::Escape($row.SamName) }
        if ($rowIsInvalid) { $skipped++; continue }

        # Skip if account already exists
        if (Resolve-AccountType $samClean) {
            Write-Warn "  '$samClean' already exists in AD — skipped."
            Write-AuditLog "BULK_CREATE" $samClean "INFO" "AlreadyExists"
            $skipped++
            continue
        }

        Write-Step "Creating: $samClean  [Type: $($row.Type)]"
        try {
            Invoke-WhatIf "BULK_CREATE" $samClean {
                switch ($row.Type) {
                    "Standard" {
                        $sp  = New-SecurePassword
                        $npe = if ($row.PwdNeverExpires) { [bool]::Parse($row.PwdNeverExpires) } else { $true }
                        New-ADUser `
                            -Name $samClean -SamAccountName $samClean `
                            -DisplayName $row.DisplayName -Description $row.Description `
                            -Path $row.OU -AccountPassword $sp `
                            -PasswordNeverExpires $npe -CannotChangePassword $true -Enabled $true | Out-Null
                    }
                    "MSA" {
                        New-ADServiceAccount `
                            -Name $samClean -SamAccountName $samClean `
                            -Description $row.Description -Path $row.OU -Enabled $true | Out-Null
                        if ($row.BindHost) {
                            Add-ADComputerServiceAccount -Identity $row.BindHost -ServiceAccount $samClean
                        }
                    }
                    "gMSA" {
                        $principals = $row.AllowedPrincipals -split "\s*,\s*" | Where-Object { $_ }
                        $interval   = if ($row.PwdInterval) { [int]$row.PwdInterval } else { 30 }
                        $params     = @{
                            Name                                   = $samClean
                            SamAccountName                         = $samClean
                            Description                            = $row.Description
                            Path                                   = $row.OU
                            DNSHostName                            = "$samClean.$($Dom.FQDN)"
                            ManagedPasswordIntervalInDays          = $interval
                            PrincipalsAllowedToRetrieveManagedPassword = $principals
                            Enabled                                = $true
                        }
                        if ($row.KerberosEncryption) { $params.KerberosEncryptionType = $row.KerberosEncryption }
                        New-ADServiceAccount @params | Out-Null
                    }
                }
                $created.Add($samClean)
            }
            Write-OK "  Created: $samClean"
            Write-AuditLog "BULK_CREATE" $samClean "SUCCESS" "Type=$($row.Type)"
            $ok++
        }
        catch {
            Write-Fail "  Failed to create '$samClean': $($_.Exception.Message)"
            Write-AuditLog "BULK_CREATE" $samClean "FAILURE" $_.Exception.Message
            $failed++

            # Offer rollback of all accounts created so far in this batch
            if (Confirm-Action "  Rollback all $($created.Count) account(s) created so far?") {
                foreach ($rollbackSam in $created) {
                    $rbType = Resolve-AccountType $rollbackSam
                    try {
                        if ($rbType -eq "Standard") { Remove-ADUser          $rollbackSam -Confirm:$false }
                        else                        { Remove-ADServiceAccount $rollbackSam -Confirm:$false }
                        Write-OK "  Rolled back: $rollbackSam"
                        Write-AuditLog "BULK_ROLLBACK" $rollbackSam "SUCCESS" ""
                    }
                    catch { Write-Fail "  Rollback failed for '$rollbackSam': $($_.Exception.Message)" }
                }
                return  # Stop processing the rest of the CSV
            }
        }
    }

    # ── Batch summary ─────────────────────────────────────────────────────────
    Write-Sub "Bulk Creation Summary"
    Write-OK   "Created : $ok"
    Write-Warn "Skipped : $skipped"
    if ($failed) { Write-Fail "Failed  : $failed" }
}

<#
.SYNOPSIS
    Verifies a KDS Root Key exists, and offers to create one if absent.
.DESCRIPTION
    Group Managed Service Accounts (gMSA) require a KDS Root Key to be present
    in the domain before any gMSA can be created. The key is used to derive the
    managed password on each authorised host.
.PARAMETER Dom  Domain info hashtable.
.NOTES
    In a lab environment, -EffectiveImmediately bypasses the normal 10-hour wait
    period required for DC replication. Do NOT use EffectiveImmediately in production.
#>
function Assert-KDSRootKey {
    param([hashtable]$Dom)
    try {
        $key = Get-KdsRootKey -EA Stop
        if ($key) { Write-OK "KDS Root Key found — gMSA creation can proceed."; return }
        throw "No KDS Root Key present."
    }
    catch {
        Write-Fail "No KDS Root Key found in the domain!"
        Write-Info "gMSA accounts require a KDS Root Key to derive managed passwords."
        if (Confirm-Action "Create a KDS Root Key now?") {
            $isLab = Confirm-Action "Is this a lab/test environment? (skips 10-hour replication wait)"
            if ($isLab) {
                # EffectiveImmediately: KDS key is available immediately — LAB ONLY
                Add-KdsRootKey -EffectiveImmediately | Out-Null
                Write-Warn "KDS Root Key created with EffectiveImmediately — DO NOT use in production!"
            }
            else {
                # Back-date by 10 hours to satisfy the replication propagation check
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
                Write-OK "KDS Root Key created — effective now (with -10h back-date)."
            }
            Write-AuditLog "KDS_KEY_CREATE" $Dom.FQDN "SUCCESS" "Lab=$isLab"
        }
        else { throw "gMSA creation requires a KDS Root Key. Creation aborted." }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  MANAGE MODULE — Full lifecycle management of existing accounts
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Manage submenu — look up an account then present all available management actions.
.DESCRIPTION
    Loads the target account type once, then loops through the action menu until
    the operator chooses Back, or the account is deleted.
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-ManageMenu {
    param([hashtable]$Dom)

    Write-Header "MANAGE SERVICE ACCOUNT"
    $sam  = Read-SAMName "SAM Account Name to manage"
    $type = Resolve-AccountType $sam

    if (-not $type) {
        Write-Fail "'$sam' was not found in Active Directory."
        Write-AuditLog "MANAGE_LOOKUP" $sam "FAILURE" "NotFound"
        Pause-Screen; return
    }
    Write-OK "Found: $sam  (Type: $type)"

    :manageLoop while ($true) {
        $action = Read-Choice "Action for $sam [$type]:" @(
            "View full details + PSO + security flags",   # 0
            "Enable / Disable",                            # 1
            "Unlock account",                              # 2
            "Reset password             (Standard only)", # 3
            "Bulk password rotation     (Standard only)", # 4
            "Modify description / display name",          # 5
            "Modify department / owner",                  # 6
            "Manage group memberships",                   # 7
            "Manage SPNs               (Standard only)",  # 8
            "Manage gMSA principals    (gMSA only)",      # 9
            "Rename account",                             # 10
            "Move to different OU",                       # 11
            "Logon workstation restriction",              # 12
            "Account expiration date",                    # 13
            "AD Recycle Bin restore",                     # 14
            "Check AD replication status",                # 15
            "Delete account (permanent)",                 # 16
            "← Back to Main Menu"                        # 17
        )

        switch ($action) {
            # ── View details ────────────────────────────────────────────────
            0 { Show-AccountDetails $sam $type; Pause-Screen }

            # ── Enable / Disable toggle ──────────────────────────────────────
            1 {
                if (-not (Assert-WriteAllowed)) { Pause-Screen; continue }
                try {
                    Invoke-WhatIf "TOGGLE_ENABLE" $sam {
                        if ($type -eq "Standard") {
                            $current = (Get-ADUser $sam -Properties Enabled).Enabled
                            Set-ADUser $sam -Enabled (-not $current)
                        }
                        else {
                            $current = (Get-ADServiceAccount $sam -Properties Enabled).Enabled
                            Set-ADServiceAccount $sam -Enabled (-not $current)
                        }
                        $newState = if (-not $current) { "ENABLED" } else { "DISABLED" }
                        Write-OK "Account is now $newState."
                        Write-AuditLog "TOGGLE_ENABLE" $sam "SUCCESS" "NewState=$newState"
                    }
                }
                catch {}
                Pause-Screen
            }

            # ── Unlock ──────────────────────────────────────────────────────
            2 {
                if ($type -ne "Standard") { Write-Warn "Unlock is only applicable to Standard accounts."; Pause-Screen; continue }
                if (-not (Assert-WriteAllowed)) { Pause-Screen; continue }
                try {
                    Invoke-WhatIf "UNLOCK" $sam {
                        Unlock-ADAccount -Identity $sam
                        Write-OK "Account unlocked."
                        Write-AuditLog "UNLOCK" $sam "SUCCESS" ""
                    }
                }
                catch {}
                Pause-Screen
            }

            # ── Password reset ───────────────────────────────────────────────
            3 {
                if ($type -ne "Standard") { Write-Warn "Password reset is only applicable to Standard accounts."; Pause-Screen; continue }
                if (-not (Assert-WriteAllowed)) { Pause-Screen; continue }
                if (Confirm-Action "Reset password for '$sam'?") {
                    try {
                        Invoke-WhatIf "PASSWORD_RESET" $sam {
                            $sp = New-SecurePassword
                            Set-ADAccountPassword $sam -NewPassword $sp -Reset
                            Write-OK "New password: $(Get-PlainText $sp)"
                            Write-Warn "Copy this to your vault NOW — it will not be shown again."
                            Write-AuditLog "PASSWORD_RESET" $sam "SUCCESS" ""
                        }
                    }
                    catch {}
                }
                Pause-Screen
            }

            # ── Bulk password rotation ───────────────────────────────────────
            4 {
                if (-not (Assert-WriteAllowed)) { Pause-Screen; continue }
                Invoke-BulkPasswordRotation
                Pause-Screen
            }

            # ── Description / Display Name ───────────────────────────────────
            5 {
                if (-not (Assert-WriteAllowed)) { Pause-Screen; continue }
                $newDesc = Read-Host "  New description (ENTER to skip)"
                $newDisp = Read-Host "  New display name (ENTER to skip)"
                try {
                    Invoke-WhatIf "MODIFY_ATTRS" $sam {
                        if ($type -eq "Standard") {
                            $params = @{}
                            if ($newDesc) { $params.Description = $newDesc }
                            if ($newDisp) { $params.DisplayName = $newDisp }
                            if ($params.Count) { Set-ADUser $sam @params }
                        }
                        else { if ($newDesc) { Set-ADServiceAccount $sam -Description $newDesc } }
                        Write-OK "Attributes updated."
                        Write-AuditLog "MODIFY_ATTRS" $sam "SUCCESS" "Desc='$newDesc' Name='$newDisp'"
                    }
                }
                catch {}
                Pause-Screen
            }

            # ── Department / Owner ───────────────────────────────────────────
            6 {
                if ($type -ne "Standard") { Write-Warn "N/A for $type accounts."; Pause-Screen; continue }
                if (-not (Assert-WriteAllowed)) { Pause-Screen; continue }
                $dept   = Read-Host "  Department (ENTER to skip)"
                $ownerSam = Read-Host "  Owner SAM Account Name (ENTER to skip)"
                try {
                    Invoke-WhatIf "MODIFY_DEPT" $sam {
                        $params = @{}
                        if ($dept) { $params.Department = $dept }
                        if ($ownerSam) {
                            try   { $params.ManagedBy = (Get-ADUser $ownerSam -EA Stop).DistinguishedName }
                            catch { Write-Warn "Owner '$ownerSam' not found in AD — skipped." }
                        }
                        if ($params.Count) { Set-ADUser $sam @params }
                        Write-OK "Updated."
                        Write-AuditLog "MODIFY_DEPT" $sam "SUCCESS" "Dept=$dept Owner=$ownerSam"
                    }
                }
                catch {}
                Pause-Screen
            }

            # ── Group memberships ────────────────────────────────────────────
            7 { Invoke-GroupAssignment $sam $type; Pause-Screen }

            # ── SPNs ─────────────────────────────────────────────────────────
            8 {
                if ($type -ne "Standard") { Write-Warn "SPN management is only for Standard accounts."; Pause-Screen; continue }
                $spnAction = Read-Choice "SPN operation:" @("Add", "Remove", "List") 0
                switch ($spnAction) {
                    0 { if (Assert-WriteAllowed) { Invoke-SPNManagement $sam "add" } }
                    1 { if (Assert-WriteAllowed) { Invoke-SPNManagement $sam "remove" } }
                    2 {
                        $spns = (Get-ADUser $sam -Properties ServicePrincipalName).ServicePrincipalName
                        if ($spns) { $spns | ForEach-Object { Write-Host "  · $_" -ForegroundColor Cyan } }
                        else       { Write-Info "No SPNs registered on '$sam'." }
                    }
                }
                Pause-Screen
            }

            # ── gMSA Principals ──────────────────────────────────────────────
            9 {
                if ($type -ne "gMSA") { Write-Warn "gMSA principal management is only for gMSA accounts."; Pause-Screen; continue }
                $pAction = Read-Choice "Principal operation:" @("Add", "Remove", "List") 0
                $principal = if ($pAction -lt 2) { Read-Host "  Principal name (computer or group)" } else { "" }
                try {
                    switch ($pAction) {
                        0 {
                            Set-ADServiceAccount $sam -PrincipalsAllowedToRetrieveManagedPassword @{ Add = $principal }
                            Write-OK "Principal '$principal' added."
                            Write-AuditLog "GMSA_PRINCIPAL_ADD" $sam "SUCCESS" $principal
                        }
                        1 {
                            Set-ADServiceAccount $sam -PrincipalsAllowedToRetrieveManagedPassword @{ Remove = $principal }
                            Write-OK "Principal '$principal' removed."
                            Write-AuditLog "GMSA_PRINCIPAL_REMOVE" $sam "SUCCESS" $principal
                        }
                        2 {
                            $pp = (Get-ADServiceAccount $sam -Properties PrincipalsAllowedToRetrieveManagedPassword).PrincipalsAllowedToRetrieveManagedPassword
                            if ($pp) { $pp | ForEach-Object { Write-Host "  · $_" } }
                            else     { Write-Info "No principals configured." }
                        }
                    }
                }
                catch { Write-Fail $_.Exception.Message }
                Pause-Screen
            }

            # ── Rename ───────────────────────────────────────────────────────
            10 {
                if (-not (Assert-WriteAllowed)) { Pause-Screen; continue }
                $newSam = Read-SAMName "New SAM Account Name"
                if (Confirm-Action "Rename '$sam' to '$newSam'?") {
                    try {
                        Invoke-WhatIf "RENAME" $sam {
                            if ($type -eq "Standard") {
                                Rename-ADObject (Get-ADUser $sam).DistinguishedName -NewName $newSam
                                Set-ADUser $newSam -SamAccountName $newSam
                            }
                            else {
                                Rename-ADObject (Get-ADServiceAccount $sam).DistinguishedName -NewName $newSam
                            }
                            Write-OK "Renamed to '$newSam'."
                            Write-AuditLog "RENAME" $sam "SUCCESS" "New=$newSam"
                            $sam = $newSam  # Update loop variable so subsequent operations use new name
                        }
                    }
                    catch {}
                }
                Pause-Screen
            }

            # ── Move OU ──────────────────────────────────────────────────────
            11 {
                if (-not (Assert-WriteAllowed)) { Pause-Screen; continue }
                $targetOU = Read-NonEmpty "Target OU (Distinguished Name)"
                if (-not (Get-ValidatedOU $targetOU)) { Write-Fail "OU not found in AD."; Pause-Screen; continue }
                if (Confirm-Action "Move '$sam' to '$targetOU'?") {
                    try {
                        Invoke-WhatIf "MOVE_OU" $sam {
                            $dn = if ($type -eq "Standard") { (Get-ADUser $sam).DistinguishedName }
                                  else                      { (Get-ADServiceAccount $sam).DistinguishedName }
                            Move-ADObject -Identity $dn -TargetPath $targetOU
                            Write-OK "Account moved."
                            Write-AuditLog "MOVE_OU" $sam "SUCCESS" "Target=$targetOU"
                        }
                    }
                    catch {}
                }
                Pause-Screen
            }

            # ── Logon workstation restriction ────────────────────────────────
            12 {
                if ($type -ne "Standard") { Write-Warn "Logon restrictions are only for Standard accounts."; Pause-Screen; continue }
                $current = (Get-ADUser $sam -Properties LogonWorkstations).LogonWorkstations
                Write-Info "Current restriction: $(Get-Coalesce $current 'Unrestricted (all workstations)')"
                $wsAction = Read-Choice "Action:" @("Set restriction (specific computers)", "Clear restriction (allow all)", "View only") 2
                if (Assert-WriteAllowed) {
                    switch ($wsAction) {
                        0 {
                            $computers = Read-Host "  Allowed computers (comma-separated)"
                            try {
                                Invoke-WhatIf "SET_LOGON_WS" $sam {
                                    Set-ADUser $sam -LogonWorkstations $computers
                                    Write-OK "Restriction set."
                                    Write-AuditLog "SET_LOGON_WS" $sam "SUCCESS" $computers
                                }
                            }
                            catch {}
                        }
                        1 {
                            try {
                                Invoke-WhatIf "CLEAR_LOGON_WS" $sam {
                                    Set-ADUser $sam -LogonWorkstations $null
                                    Write-OK "Restriction cleared — account can log on from any workstation."
                                    Write-AuditLog "CLEAR_LOGON_WS" $sam "SUCCESS" ""
                                }
                            }
                            catch {}
                        }
                    }
                }
                Pause-Screen
            }

            # ── Account expiration ───────────────────────────────────────────
            13 {
                if ($type -ne "Standard") { Write-Warn "Account expiry is only for Standard accounts."; Pause-Screen; continue }
                $expAction = Read-Choice "Expiry action:" @("Set expiry date", "Clear (never expires)", "View current") 2
                if (Assert-WriteAllowed) {
                    switch ($expAction) {
                        0 {
                            $dateStr = Read-NonEmpty "Expiry date (yyyy-MM-dd)"
                            try {
                                Invoke-WhatIf "SET_EXPIRY" $sam {
                                    Set-ADUser $sam -AccountExpirationDate ([datetime]::Parse($dateStr))
                                    Write-OK "Account will expire on $dateStr."
                                    Write-AuditLog "SET_EXPIRY" $sam "SUCCESS" "Date=$dateStr"
                                }
                            }
                            catch {}
                        }
                        1 {
                            try {
                                Invoke-WhatIf "CLEAR_EXPIRY" $sam {
                                    Set-ADUser $sam -AccountExpirationDate $null
                                    Write-OK "Account expiry cleared."
                                    Write-AuditLog "CLEAR_EXPIRY" $sam "SUCCESS" ""
                                }
                            }
                            catch {}
                        }
                        2 {
                            $exp = (Get-ADUser $sam -Properties AccountExpirationDate).AccountExpirationDate
                            Write-Info "Current expiry: $(Get-Coalesce $exp 'Never')"
                        }
                    }
                }
                Pause-Screen
            }

            # ── Recycle Bin restore ──────────────────────────────────────────
            14 { Invoke-RecycleBinRestore $Dom; Pause-Screen }

            # ── Replication status ───────────────────────────────────────────
            15 { Test-ADReplication $sam $Dom; Pause-Screen }

            # ── Permanent delete ─────────────────────────────────────────────
            16 {
                if (-not (Assert-WriteAllowed)) { Pause-Screen; continue }
                Write-Fail "WARNING: This will PERMANENTLY DELETE '$sam' from Active Directory."
                Write-Warn "Run Dependency Mapping first to ensure no services depend on this account."
                if (-not (Confirm-Action "Are you absolutely sure you want to delete '$sam'?")) {
                    Pause-Screen; continue
                }
                # Require the operator to type the account name as an additional safeguard
                $typed = Read-Host "  Type the account name exactly to confirm deletion"
                if ($typed -ne $sam) {
                    Write-Warn "Name mismatch — deletion cancelled."
                    Pause-Screen; continue
                }
                try {
                    Invoke-WhatIf "DELETE" $sam {
                        if ($type -eq "Standard") { Remove-ADUser          $sam -Confirm:$false }
                        else                      { Remove-ADServiceAccount $sam -Confirm:$false }
                        Write-OK "Account '$sam' deleted."
                        Write-AuditLog "DELETE" $sam "SUCCESS" "Type=$type"
                    }
                }
                catch {}
                Pause-Screen
                break manageLoop  # Account is gone — exit the manage loop
            }

            # ── Back ─────────────────────────────────────────────────────────
            17 { break manageLoop }
        }
    }
}

<#
.SYNOPSIS
    Displays comprehensive details for an account, including all security-relevant flags.
.DESCRIPTION
    For Standard accounts: retrieves ~30 properties and displays them in a table,
    followed by PSO details, SID History warnings, and a security flag summary.
    For MSA/gMSA: shows service-account-specific properties.
.PARAMETER Sam   SAM Account Name.
.PARAMETER Type  "Standard" | "MSA" | "gMSA"
#>
function Show-AccountDetails {
    param([string]$Sam, [string]$Type)
    Write-Sub "Details: $Sam"
    try {
        if ($Type -eq "Standard") {
            $u = Get-ADUser $Sam -Properties `
                DisplayName, Description, Department, ManagedBy, Enabled, PasswordNeverExpires,
                PasswordLastSet, PasswordExpired, LockedOut, LastLogonDate, AccountExpirationDate,
                BadLogonCount, ServicePrincipalName, MemberOf, LogonWorkstations, adminCount,
                DistinguishedName, Created, Modified, AllowReversiblePasswordEncryption,
                PasswordNotRequired, TrustedForDelegation, TrustedToAuthForDelegation,
                DoesNotRequirePreAuth, KerberosEncryptionType, SIDHistory,
                ProtectedFromAccidentalDeletion, "msDS-AllowedToDelegateTo"

            # Build a display hashtable with PS 5.1-compatible null coalescing
            @{
                "SAM"                = $u.SamAccountName
                "DisplayName"        = $u.DisplayName
                "Description"        = $u.Description
                "Department"         = $u.Department
                "ManagedBy"          = $u.ManagedBy -replace '^CN=([^,]+).*', '$1'
                "Enabled"            = $u.Enabled
                "LockedOut"          = $u.LockedOut
                "PwdNeverExpires"    = $u.PasswordNeverExpires
                "PwdLastSet"         = $u.PasswordLastSet
                "PwdExpired"         = $u.PasswordExpired
                "LastLogon"          = Get-Coalesce $u.LastLogonDate "Never"
                "AccountExpires"     = Get-Coalesce $u.AccountExpirationDate "Never"
                "BadLogonCount"      = $u.BadLogonCount
                "LogonWorkstations"  = Get-Coalesce $u.LogonWorkstations "Unrestricted"
                "adminCount"         = $u.adminCount
                "SIDHistoryCount"    = @($u.SIDHistory).Count
                "UnconstrainedDeleg" = $u.TrustedForDelegation
                "ConstrainedDeleg"   = $u.TrustedToAuthForDelegation
                "ASREPRoastable"     = $u.DoesNotRequirePreAuth
                "ReversibleEnc"      = $u.AllowReversiblePasswordEncryption
                "PASSWD_NOTREQD"     = $u.PasswordNotRequired
                "KerberosEnc"        = $u.KerberosEncryptionType
                "SPNCount"           = @($u.ServicePrincipalName).Where({ $_ }).Count
                "GroupCount"         = @($u.MemberOf).Where({ $_ }).Count
                "ProtectedFromDel"   = $u.ProtectedFromAccidentalDeletion
                "DN"                 = $u.DistinguishedName
                "Created"            = $u.Created
                "Modified"           = $u.Modified
            }.GetEnumerator() | Sort-Object Name | ForEach-Object {
                Write-Host ("  {0,-22}: {1}" -f $_.Key, $_.Value) -ForegroundColor White
            }

            # ── PSO / Fine-Grained Password Policy ──────────────────────────
            Write-Sub "Password Policy"
            $pso = Get-AccountPSO $Sam
            if ($pso) {
                Write-Warn "PSO '$($pso.Name)' is applied — MaxPwdAge: $($pso.MaxPasswordAge)  MinLen: $($pso.MinPasswordLength)  Lockout: $($pso.LockoutThreshold)"
            }
            else { Write-Info "No PSO applied — domain default password policy is in effect." }

            # ── SID History warning ──────────────────────────────────────────
            $sidCount = @($u.SIDHistory).Count
            if ($sidCount -gt 0) {
                Write-Sub "SID History — SECURITY WARNING"
                Write-Fail "This account carries $sidCount legacy SID(s) from a previous domain."
                Write-Fail "SID History can grant hidden elevated privileges. Remove if source domain is decommissioned."
                $u.SIDHistory | ForEach-Object { Write-Warn "  SID: $($_.Value)" }
            }

            # ── Security flag summary ─────────────────────────────────────────
            Write-Sub "Security Flags"
            $flags = @()
            if ($u.TrustedForDelegation)              { $flags += "⚠ UNCONSTRAINED DELEGATION — HIGH RISK (Kerberos ticket theft possible)" }
            if ($u.DoesNotRequirePreAuth)              { $flags += "⚠ AS-REP ROASTABLE — attacker can request TGT without credentials" }
            if ($u.AllowReversiblePasswordEncryption)  { $flags += "⚠ REVERSIBLE ENCRYPTION — password stored in near-plaintext" }
            if ($u.PasswordNotRequired)                { $flags += "⚠ PASSWD_NOTREQD — blank password may be accepted" }
            if ($u.adminCount -eq 1)                   { $flags += "⚠ SHADOW ADMIN — adminCount=1 grants elevated ACLs via AdminSDHolder" }
            if (@($u.SIDHistory).Count -gt 0)          { $flags += "⚠ HAS SID HISTORY — may have legacy domain privileges" }
            if (@($u.ServicePrincipalName).Where({ $_ }).Count -gt 0) {
                $flags += "ℹ KERBEROASTABLE — account has SPNs; ensure AES256 encryption is set"
            }
            if ($flags) { $flags | ForEach-Object { Write-Warn $_ } }
            else        { Write-OK "No critical security flags detected." }
        }
        else {
            # MSA / gMSA detail view
            $sa = Get-ADServiceAccount $Sam -Properties `
                Description, Enabled, ManagedPasswordIntervalInDays, KerberosEncryptionType,
                PrincipalsAllowedToRetrieveManagedPassword, DNSHostName, Created, Modified,
                ObjectClass, DistinguishedName

            @{
                "SAM"          = $sa.SamAccountName
                "ObjectClass"  = $sa.ObjectClass
                "Description"  = $sa.Description
                "Enabled"      = $sa.Enabled
                "DNSHost"      = $sa.DNSHostName
                "PwdInterval"  = $sa.ManagedPasswordIntervalInDays
                "KerberosEnc"  = $sa.KerberosEncryptionType
                "DN"           = $sa.DistinguishedName
                "Created"      = $sa.Created
                "Modified"     = $sa.Modified
            }.GetEnumerator() | Sort-Object Name | ForEach-Object {
                Write-Host ("  {0,-16}: {1}" -f $_.Key, $_.Value) -ForegroundColor White
            }
        }
        Write-AuditLog "VIEW_DETAILS" $Sam "INFO" ""
    }
    catch { Write-Fail "Failed to retrieve account details: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Add to, remove from, or list the group memberships of a service account.
.PARAMETER Sam   SAM Account Name.
.PARAMETER Type  "Standard" | "MSA" | "gMSA"
#>
function Invoke-GroupAssignment {
    param([string]$Sam, [string]$Type)
    $action = Read-Choice "Group management:" @("Add to group", "Remove from group", "List current memberships") 0

    switch ($action) {
        0 {
            if (-not (Assert-WriteAllowed)) { return }
            do {
                $group = Read-Host "  Group name (ENTER to stop)"
                if (-not $group) { break }
                try {
                    if ($Type -eq "Standard") { Add-ADGroupMember $group -Members $Sam }
                    else                      { Add-ADGroupMember $group -Members (Get-ADServiceAccount $Sam) }
                    Write-OK "Added '$Sam' to '$group'."
                    Write-AuditLog "GROUP_ADD" $Sam "SUCCESS" "Group=$group"
                }
                catch { Write-Fail $_.Exception.Message }
            } while ($true)
        }
        1 {
            if (-not (Assert-WriteAllowed)) { return }
            do {
                $group = Read-Host "  Group name (ENTER to stop)"
                if (-not $group) { break }
                try {
                    if ($Type -eq "Standard") { Remove-ADGroupMember $group -Members $Sam -Confirm:$false }
                    else                      { Remove-ADGroupMember $group -Members (Get-ADServiceAccount $Sam) -Confirm:$false }
                    Write-OK "Removed '$Sam' from '$group'."
                    Write-AuditLog "GROUP_REMOVE" $Sam "SUCCESS" "Group=$group"
                }
                catch { Write-Fail $_.Exception.Message }
            } while ($true)
        }
        2 {
            try {
                $memberships = if ($Type -eq "Standard") {
                    (Get-ADUser $Sam -Properties MemberOf).MemberOf
                }
                else {
                    (Get-ADServiceAccount $Sam -Properties MemberOf).MemberOf
                }
                if ($memberships) {
                    $memberships | ForEach-Object {
                        Write-Host "  · $($_ -replace '^CN=([^,]+).*','$1')" -ForegroundColor Cyan
                    }
                }
                else { Write-Info "Account is not a member of any groups." }
            }
            catch { Write-Fail $_.Exception.Message }
        }
    }
}

<#
.SYNOPSIS  Register or remove Service Principal Names (SPNs) on a Standard account.
.DESCRIPTION
    SPNs are required for Kerberos service ticket issuance. Duplicate SPNs across
    accounts cause authentication failures. Use Test-DuplicateSPNs to check.
    Format examples:  HTTP/webserver.corp.com   MSSQLSvc/sqlserver.corp.com:1433
.PARAMETER Sam   SAM Account Name.
.PARAMETER Mode  "add" or "remove"
#>
function Invoke-SPNManagement {
    param([string]$Sam, [string]$Mode)
    Write-Info "SPN format examples: HTTP/webserver.domain.com   MSSQLSvc/sqlserver:1433"
    do {
        $spn = Read-Host "  SPN to $Mode (ENTER to stop)"
        if (-not $spn) { break }
        try {
            $operation = if ($Mode -eq "add") { "Add" } else { "Remove" }
            Set-ADUser $Sam -ServicePrincipalNames @{ $operation = $spn }
            Write-OK "SPN '$spn' ${Mode}ed successfully."
            Write-AuditLog "SPN_$($Mode.ToUpper())" $Sam "SUCCESS" $spn
        }
        catch { Write-Fail $_.Exception.Message }
    } while ($true)
}

<#
.SYNOPSIS  Resets passwords for multiple Standard accounts in one operation.
.DESCRIPTION
    Generates a new cryptographically random password for each account.
    Results can be exported to a text file on the Desktop for vault import.
.NOTES     Only applicable to Standard (user-based) service accounts.
#>
function Invoke-BulkPasswordRotation {
    Write-Sub "Bulk Password Rotation"
    $raw      = Read-NonEmpty "Account SAM names (comma-separated)"
    $accounts = $raw -split "\s*,\s*" | Where-Object { $_ }
    $results  = @()

    foreach ($account in $accounts) {
        if ((Resolve-AccountType $account) -ne "Standard") {
            Write-Warn "  '$account' is not a Standard account — skipped."
            continue
        }
        try {
            Invoke-WhatIf "BULK_PWD_ROTATE" $account {
                $sp = New-SecurePassword
                Set-ADAccountPassword $account -NewPassword $sp -Reset
                $results += [PSCustomObject]@{
                    Account     = $account
                    NewPassword = Get-PlainText $sp
                    Status      = "OK"
                }
                Write-OK "  $account — password rotated."
                Write-AuditLog "PASSWORD_RESET" $account "SUCCESS" "BulkRotation"
            }
        }
        catch {
            $results += [PSCustomObject]@{
                Account     = $account
                NewPassword = "ERROR"
                Status      = $_.Exception.Message
            }
            Write-Fail "  $account — $($_.Exception.Message)"
        }
    }

    if ($results -and (Confirm-Action "Export new passwords to Desktop?")) {
        $exportPath = Join-Path ([Environment]::GetFolderPath("Desktop")) `
            "BulkPwdRotation_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        ($results | Format-Table -AutoSize | Out-String) | Set-Content $exportPath -Encoding UTF8
        Write-Warn "Saved: $exportPath"
        Write-Warn "▶ Move this file to your vault NOW, then delete it."
    }
}

<#
.SYNOPSIS  Restores a deleted service account from the AD Recycle Bin.
.DESCRIPTION
    Lists the 30 most recently deleted user/MSA/gMSA objects and allows the
    operator to select one for restoration to its original OU.
    Requires the AD Recycle Bin optional feature to be enabled.
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-RecycleBinRestore {
    param([hashtable]$Dom)
    Write-Sub "AD Recycle Bin Restore"
    try {
        # Verify the Recycle Bin feature is enabled in this domain
        $rb = Get-ADOptionalFeature -Filter { Name -eq "Recycle Bin Feature" } -EA Stop
        if ($rb.EnabledScopes.Count -eq 0) {
            Write-Fail "AD Recycle Bin is NOT enabled on this domain."
            Write-Info "Enable with: Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $($Dom.FQDN)"
            return
        }

        # List recently deleted service-account-type objects
        $deleted = Get-ADObject -Filter { IsDeleted -eq $true } -IncludeDeletedObjects `
                       -Properties SamAccountName, whenChanged, LastKnownParent, ObjectClass |
                   Where-Object { $_.ObjectClass -in @("user", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount") } |
                   Sort-Object whenChanged -Descending | Select-Object -First 30

        if (-not $deleted) { Write-Info "No deleted service accounts found in the Recycle Bin."; return }

        $deleted | Format-Table Name, ObjectClass, whenChanged, LastKnownParent -AutoSize
        $name = Read-Host "  Account name to restore (ENTER to cancel)"
        if (-not $name) { return }

        $target = $deleted | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $target) { Write-Fail "Account '$name' not found in the deleted list."; return }

        if (Assert-WriteAllowed -and (Confirm-Action "Restore '$name' to '$($target.LastKnownParent)'?")) {
            Invoke-WhatIf "RECYCLE_BIN_RESTORE" $name {
                Restore-ADObject $target.DistinguishedName
                Write-OK "Account '$name' restored to its original OU."
                Write-AuditLog "RECYCLE_BIN_RESTORE" $name "SUCCESS" "OU=$($target.LastKnownParent)"
            }
        }
    }
    catch { Write-Fail "Recycle Bin operation failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Checks whether a Standard account object is present on every Domain Controller.
.DESCRIPTION
    Queries each DC for the account and reports Last Modified time. DCs that do not
    yet have the object have not yet received the replication for the latest change.
    If replication is lagging, the suggested remediation command is shown.
.PARAMETER Sam  SAM Account Name to check.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-ADReplication {
    param([string]$Sam, [hashtable]$Dom)
    Write-Sub "AD Replication Status: $Sam"
    try {
        $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
        Write-Info "Querying $($dcs.Count) Domain Controller(s)..."

        $results = foreach ($dc in $dcs) {
            try {
                $obj = Get-ADUser $Sam -Server $dc -Properties Modified -EA Stop
                [PSCustomObject]@{ DC = $dc; Found = $true; LastModified = $obj.Modified; Status = "OK" }
            }
            catch {
                [PSCustomObject]@{ DC = $dc; Found = $false; LastModified = $null; Status = $_.Exception.Message }
            }
        }

        $results | Format-Table DC, Found, LastModified, Status -AutoSize
        $missing = $results | Where-Object { $_.Found -eq $false }

        if ($missing) {
            Write-Warn "$($missing.Count) DC(s) do not yet have this account. Force replication with:"
            Write-Info "  repadmin /syncall /AdeP"
        }
        else { Write-OK "Account is present and consistent on all Domain Controllers." }

        Write-AuditLog "REPLICATION_CHECK" $Sam "INFO" "DCs=$($dcs.Count) Missing=$($missing.Count)"
    }
    catch { Write-Fail "Replication check failed: $($_.Exception.Message)" }
}

# ══════════════════════════════════════════════════════════════════════════════
#  TEST MODULE — Health and compliance testing for service accounts
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS  Entry point for the Test submenu.
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-TestMenu {
    param([hashtable]$Dom)
    Write-Header "TEST / CHECK"
    $choice = Read-Choice "Select a test:" @(
        "Account health check",
        "Password status + PSO",
        "Duplicate SPN scan (domain-wide)",
        "SPN conflict scan (same service/host, multiple accounts)",
        "gMSA password retrieval test (run on authorised host)",
        "MSA bound-host validation",
        "Kerberos delegation check",
        "Privileged group membership scan",
        "Protected Users group impact check",
        "Stale accounts (no logon > N days)",
        "Never-logged-on accounts",
        "Password age scan (not rotated > N days)",
        "Naming convention compliance",
        "Bulk OU status report",
        "← Back"
    )
    switch ($choice) {
        0  { Test-AccountHealth    (Read-SAMName "SAM Account Name") }
        1  { Test-PasswordStatus   (Read-SAMName "SAM Account Name") }
        2  { Test-DuplicateSPNs }
        3  { Test-MultiSPNConflicts }
        4  {
            Write-Warn "This test must run ON a host that is in PrincipalsAllowedToRetrieveManagedPassword."
            Test-gMSARetrieval (Read-SAMName "gMSA SAM Account Name")
        }
        5  { Test-MSABoundHost   $Dom }
        6  { Test-KerberosDelegation (Read-SAMName "SAM Account Name") }
        7  { Test-PrivilegedGroupScan }
        8  { Test-ProtectedUsersCheck $Dom }
        9  { Test-StaleAccounts ([int](Read-NonEmpty "Stale threshold (days)" "90")) $Dom.DN }
        10 { Test-NeverLoggedOn  $Dom.DN }
        11 { Test-PasswordAge    ([int](Read-NonEmpty "Max password age (days)" "365")) $Dom.DN }
        12 { Test-NamingCompliance $Dom }
        13 { Test-BulkStatus     (Read-NonEmpty "OU Distinguished Name") }
        14 { return }
    }
    Pause-Screen
}

<#
.SYNOPSIS
    Runs a focused health check against a single account and reports each dimension.
.DESCRIPTION
    Tests: Enabled, not locked out, password not expired, PasswordNeverExpires, bad logon
    count, pre-authentication required, no unconstrained delegation, PASSWD_NOTREQD,
    no reversible encryption, adminCount=0, and no SID History.
.PARAMETER Sam  SAM Account Name to check.
#>
function Test-AccountHealth {
    param([string]$Sam)
    Write-Sub "Health Check: $Sam"
    $type = Resolve-AccountType $Sam
    if (-not $type) { Write-Fail "'$Sam' not found in AD."; return }

    if ($type -eq "Standard") {
        $u = Get-ADUser $Sam -Properties `
            Enabled, LockedOut, PasswordExpired, PasswordNeverExpires, PasswordLastSet,
            AccountExpirationDate, LastLogonDate, BadLogonCount, DoesNotRequirePreAuth,
            TrustedForDelegation, PasswordNotRequired, AllowReversiblePasswordEncryption,
            adminCount, SIDHistory

        # Display each check as a pass/fail row
        @{
            "Enabled"                = @{ V = $u.Enabled;                             P = $u.Enabled }
            "Not Locked Out"         = @{ V = -not $u.LockedOut;                      P = -not $u.LockedOut }
            "Pwd Not Expired"        = @{ V = -not $u.PasswordExpired;                P = -not $u.PasswordExpired }
            "Pwd Never Expires"      = @{ V = $u.PasswordNeverExpires;                P = $u.PasswordNeverExpires }
            "Bad Logons < 5"         = @{ V = $u.BadLogonCount;                       P = $u.BadLogonCount -lt 5 }
            "Pre-Auth Required"      = @{ V = -not $u.DoesNotRequirePreAuth;          P = -not $u.DoesNotRequirePreAuth }
            "No Unconstrained Deleg" = @{ V = -not $u.TrustedForDelegation;           P = -not $u.TrustedForDelegation }
            "PASSWD_NOTREQD=false"   = @{ V = -not $u.PasswordNotRequired;            P = -not $u.PasswordNotRequired }
            "No Reversible Enc."     = @{ V = -not $u.AllowReversiblePasswordEncryption; P = -not $u.AllowReversiblePasswordEncryption }
            "adminCount=0"           = @{ V = $u.adminCount -ne 1;                    P = $u.adminCount -ne 1 }
            "No SID History"         = @{ V = @($u.SIDHistory).Count -eq 0;           P = @($u.SIDHistory).Count -eq 0 }
        }.GetEnumerator() | Sort-Object Name | ForEach-Object {
            if ($_.Value.P) { Write-OK  ("{0,-28}: {1}" -f $_.Key, $_.Value.V) }
            else            { Write-Fail ("{0,-28}: {1}" -f $_.Key, $_.Value.V) }
        }
    }
    else {
        $sa = Get-ADServiceAccount $Sam -Properties Enabled
        if ($sa.Enabled) { Write-OK "Enabled: True" }
        else             { Write-Fail "Enabled: False" }
        Write-Info "MSA/gMSA password management is fully automated — no password checks needed."
    }
    Write-AuditLog "TEST_HEALTH" $Sam "INFO" "Type=$type"
}

<#
.SYNOPSIS
    Shows the full password status for a Standard account, including PSO-derived expiry.
.DESCRIPTION
    Determines the effective MaxPasswordAge from the Fine-Grained PSO (if any) or the
    domain default policy, then calculates days remaining and highlights urgency.
.PARAMETER Sam  SAM Account Name.
#>
function Test-PasswordStatus {
    param([string]$Sam)
    Write-Sub "Password Status: $Sam"
    try {
        $u   = Get-ADUser $Sam -Properties PasswordLastSet, PasswordNeverExpires, PasswordExpired
        $pso = Get-AccountPSO $Sam
        $pol = if ($pso) { $pso } else { Get-ADDefaultDomainPasswordPolicy }

        # Determine effective max age — zero means never
        $maxAge = if ($u.PasswordNeverExpires -or -not $pol -or $pol.MaxPasswordAge.TotalDays -eq 0) {
            [TimeSpan]::Zero
        }
        else { $pol.MaxPasswordAge }

        $expiryDate = if ($maxAge.TotalDays -eq 0) { "Never" }
                      else { $u.PasswordLastSet + $maxAge }

        $daysLeft = if ($expiryDate -eq "Never") { [int]::MaxValue } # Treat as infinite
                    else { [int]($expiryDate - (Get-Date)).TotalDays }

        $daysDisplay = if ($daysLeft -eq [int]::MaxValue) { "∞" } else { "$daysLeft" }
        $policySource = if ($pso) { "PSO: $($pso.Name)" } else { "Domain Default Policy" }

        Write-Host "  Policy Source  : $policySource" -ForegroundColor Cyan
        Write-Host "  Last Set       : $($u.PasswordLastSet)"
        Write-Host "  Expires        : $expiryDate"

        # Colour-code the days remaining by urgency
        $colour = if ($daysLeft -eq [int]::MaxValue) { "Green" }
                  elseif ($daysLeft -lt 14)           { "Red" }
                  elseif ($daysLeft -lt 30)           { "Yellow" }
                  else                                { "Green" }
        Write-Host "  Days Remaining : $daysDisplay" -ForegroundColor $colour
        Write-Host "  Expired        : $($u.PasswordExpired)" -ForegroundColor (if ($u.PasswordExpired) { "Red" } else { "Green" })

        Write-AuditLog "TEST_PWD_STATUS" $Sam "INFO" "DaysLeft=$daysDisplay Src=$policySource"
    }
    catch { Write-Fail "Password status check failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Scans the entire domain for SPNs that are registered on more than one account.
.DESCRIPTION
    Duplicate SPNs cause Kerberos authentication failures because the KDC cannot
    determine which account to encrypt the service ticket for.
    Any duplicates found should be resolved immediately.
#>
function Test-DuplicateSPNs {
    Write-Sub "Duplicate SPN Scan (domain-wide)"
    try {
        # Collect all SPN → account mappings
        $all = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName |
               ForEach-Object {
                   $user = $_
                   $user.ServicePrincipalName | ForEach-Object {
                       [PSCustomObject]@{ SPN = $_; Account = $user.SamAccountName }
                   }
               }

        # Group by SPN and find those with more than one owning account
        $dupes = $all | Group-Object SPN | Where-Object { $_.Count -gt 1 }

        if ($dupes) {
            Write-Fail "$($dupes.Count) duplicate SPN(s) detected — these WILL cause Kerberos failures:"
            $dupes | ForEach-Object {
                Write-Fail "  $($_.Name)"
                $_.Group | ForEach-Object { Write-Host "    → $($_.Account)" -ForegroundColor Red }
            }
            Write-Warn "Remove the duplicate SPN from all but one account using Invoke-ManageMenu → SPNs."
            Write-AuditLog "TEST_DUPLICATE_SPN" "DOMAIN" "FAILURE" "Count=$($dupes.Count)"
        }
        else { Write-OK "No duplicate SPNs found."; Write-AuditLog "TEST_DUPLICATE_SPN" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "Duplicate SPN scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Finds cases where multiple accounts register SPNs for the same service/host combination.
.DESCRIPTION
    While not technically duplicates (the port suffix may differ), multiple accounts
    targeting the same host for the same service type indicate misconfiguration that
    can cause intermittent Kerberos failures depending on which ticket the KDC issues.
#>
function Test-MultiSPNConflicts {
    Write-Sub "Multi-Account SPN Conflicts (same service/host)"
    try {
        $all    = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName
        $spnMap = @{}

        foreach ($user in $all) {
            foreach ($spn in $user.ServicePrincipalName) {
                # Normalise: strip the port/instance suffix, keep service/host
                if ($spn -match "^([^/]+)/([^:]+)") {
                    $key = "$($Matches[1])/$($Matches[2])"
                    if (-not $spnMap[$key]) { $spnMap[$key] = @() }
                    $spnMap[$key] += $user.SamAccountName
                }
            }
        }

        $conflicts = $spnMap.GetEnumerator() | Where-Object { ($_.Value | Sort-Object -Unique).Count -gt 1 }

        if ($conflicts) {
            Write-Warn "$($conflicts.Count) service/host conflict(s) detected:"
            $conflicts | ForEach-Object {
                Write-Warn "  $($_.Key)"
                $_.Value | Sort-Object -Unique | ForEach-Object { Write-Host "    → $_" -ForegroundColor Yellow }
            }
            Write-AuditLog "TEST_MULTI_SPN" "DOMAIN" "FAILURE" "Conflicts=$($conflicts.Count)"
        }
        else { Write-OK "No SPN conflicts found."; Write-AuditLog "TEST_MULTI_SPN" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "SPN conflict scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Tests whether the current host can retrieve the managed password for a gMSA.
.DESCRIPTION
    Calls Test-ADServiceAccount on the local machine. The test passes only if the
    machine running this script is listed in PrincipalsAllowedToRetrieveManagedPassword.
    Run this on each authorised host after creating or modifying a gMSA.
.PARAMETER Sam  gMSA SAM Account Name.
#>
function Test-gMSARetrieval {
    param([string]$Sam)
    Write-Sub "gMSA Password Retrieval Test: $Sam"
    try {
        Test-ADServiceAccount -Identity $Sam
        Write-OK "PASSED — this host ($env:COMPUTERNAME) can successfully retrieve the managed password."
        Write-AuditLog "TEST_GMSA_RETRIEVAL" $Sam "SUCCESS" "Host=$env:COMPUTERNAME"
    }
    catch {
        Write-Fail "FAILED — this host cannot retrieve the managed password: $($_.Exception.Message)"
        Write-Warn "Ensure '$env:COMPUTERNAME`$' (computer account) is in PrincipalsAllowedToRetrieveManagedPassword."
        Write-Info "Use Manage → gMSA principals → Add to add this host."
        Write-AuditLog "TEST_GMSA_RETRIEVAL" $Sam "FAILURE" $_.Exception.Message
    }
}

<#
.SYNOPSIS
    Verifies that all MSA accounts are bound to valid, existing computer accounts.
.DESCRIPTION
    An MSA bound to a deleted or non-existent computer account is effectively
    orphaned — no host can use it and its managed password is still rotated.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-MSABoundHost {
    param([hashtable]$Dom)
    Write-Sub "MSA Bound-Host Validation"
    try {
        $msas = Get-ADServiceAccount -SearchBase $Dom.DN `
                    -Filter { ObjectClass -eq "msDS-ManagedServiceAccount" } `
                    -Properties HostComputers

        if (-not $msas) { Write-Info "No MSA accounts found in this domain."; return }

        $issues = 0
        foreach ($msa in $msas) {
            if (-not $msa.HostComputers) {
                Write-Warn "  $($msa.SamAccountName) — not bound to any host computer account!"
                $issues++
            }
            else {
                foreach ($hostDN in $msa.HostComputers) {
                    $computerName = $hostDN -replace '^CN=([^,]+).*', '$1'
                    try {
                        Get-ADComputer $computerName -EA Stop | Out-Null
                        Write-OK "  $($msa.SamAccountName) → $computerName (host account active)"
                    }
                    catch {
                        Write-Fail "  $($msa.SamAccountName) → $computerName — HOST COMPUTER ACCOUNT NOT FOUND!"
                        $issues++
                    }
                }
            }
        }
        if ($issues -eq 0) { Write-OK "All MSA bindings are valid." }
        Write-AuditLog "TEST_MSA_BOUND_HOST" "DOMAIN" (if ($issues) { "FAILURE" } else { "SUCCESS" }) "Issues=$issues"
    }
    catch { Write-Fail "MSA bound-host check failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Displays the full Kerberos delegation configuration for an account.
.DESCRIPTION
    Reports unconstrained, constrained, and resource-based constrained delegation.
    Unconstrained delegation is a HIGH RISK setting — any service ticket obtained
    by an account with unconstrained delegation can be used to impersonate any user
    to any service in the domain (modulo Protected Users restrictions).
.PARAMETER Sam  SAM Account Name.
#>
function Test-KerberosDelegation {
    param([string]$Sam)
    Write-Sub "Kerberos Delegation: $Sam"
    try {
        $u = Get-ADUser $Sam -Properties TrustedForDelegation, TrustedToAuthForDelegation, "msDS-AllowedToDelegateTo"
        Write-Host "  Unconstrained Delegation : $($u.TrustedForDelegation)" `
            -ForegroundColor (if ($u.TrustedForDelegation) { "Red" } else { "Green" })
        Write-Host "  Constrained Delegation   : $($u.TrustedToAuthForDelegation)"

        if ($u.'msDS-AllowedToDelegateTo') {
            Write-Host "  Constrained Targets:" -ForegroundColor DarkCyan
            $u.'msDS-AllowedToDelegateTo' | ForEach-Object { Write-Host "    · $_" }
        }
        if ($u.TrustedForDelegation) {
            Write-Fail "HIGH RISK: Unconstrained delegation enabled — consider switching to constrained delegation."
        }
        Write-AuditLog "TEST_DELEGATION" $Sam "INFO" "Unconstrained=$($u.TrustedForDelegation)"
    }
    catch { Write-Fail "Delegation check failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Scans all configured privileged AD groups for service account members.
.DESCRIPTION
    Service accounts should NEVER be members of privileged groups (Domain Admins,
    Account Operators, etc.). Membership in these groups violates the principle of
    least privilege and creates a large attack surface — a compromised service
    account password becomes a domain compromise.
#>
function Test-PrivilegedGroupScan {
    Write-Sub "Privileged Group Membership Scan"
    $found = $false
    foreach ($group in $CFG.AdminGroups) {
        try {
            $members = Get-ADGroupMember $group -Recursive -EA SilentlyContinue |
                       Where-Object { Test-NamingConvention $_.SamAccountName }
            if ($members) {
                Write-Warn "Service accounts found in privileged group '$group':"
                $members | ForEach-Object { Write-Fail "    $($_.SamAccountName)" }
                $found = $true
                Write-AuditLog "TEST_PRIV_GROUP" $group "FAILURE" "Count=$($members.Count)"
            }
        }
        catch {}  # Group may not exist in this domain — silently skip
    }
    if (-not $found) {
        Write-OK "No service accounts found in privileged groups."
        Write-AuditLog "TEST_PRIV_GROUP" "ALL" "SUCCESS" ""
    }
}

<#
.SYNOPSIS
    Finds service accounts that are members of the Protected Users security group.
.DESCRIPTION
    Protected Users is a hardening group but it has significant side effects that
    BREAK service account functionality:
      - No NTLM, Digest, or CredSSP authentication
      - No unconstrained Kerberos delegation
      - No RC4 session keys — AES only
      - Kerberos TGT lifetime capped at 4 hours
    Service accounts should NOT be in this group unless you have explicitly tested
    that all their services work under these restrictions.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-ProtectedUsersCheck {
    param([hashtable]$Dom)
    Write-Sub "Protected Users Group — Service Account Impact Check"
    Write-Info "Side effects for service accounts: no NTLM, no delegation, AES-only, 4h TGT."
    try {
        $affected = Get-ADGroupMember "Protected Users" -Recursive -EA Stop |
                    Where-Object { Test-NamingConvention $_.SamAccountName }
        if ($affected) {
            Write-Fail "$($affected.Count) service account(s) are in Protected Users — services may break!"
            $affected | Format-Table SamAccountName, ObjectClass -AutoSize
            Write-AuditLog "TEST_PROTECTED_USERS" "DOMAIN" "FAILURE" "Count=$($affected.Count)"
        }
        else {
            Write-OK "No service accounts found in Protected Users."
            Write-AuditLog "TEST_PROTECTED_USERS" "DOMAIN" "SUCCESS" ""
        }
    }
    catch { Write-Fail "Protected Users check failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Lists enabled service accounts that have not logged on within N days.
.PARAMETER Days  Number of days without logon before an account is considered stale.
.PARAMETER Base  AD search base (OU or domain DN).
#>
function Test-StaleAccounts {
    param([int]$Days, [string]$Base)
    Write-Sub "Stale Accounts (no logon in > $Days days)"
    $cutoff = (Get-Date).AddDays(-$Days)
    try {
        $stale = Get-ADUser -SearchBase $Base `
                     -Filter { LastLogonDate -lt $cutoff -and Enabled -eq $true } `
                     -Properties LastLogonDate, Description |
                 Where-Object { Test-NamingConvention $_.SamAccountName }

        if ($stale) {
            Write-Warn "$($stale.Count) stale account(s) found:"
            Show-Paged $stale @("SamAccountName", "LastLogonDate", "Description")
            Write-AuditLog "TEST_STALE" "DOMAIN" "FAILURE" "Count=$($stale.Count)"
        }
        else { Write-OK "No stale accounts found."; Write-AuditLog "TEST_STALE" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "Stale account scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Lists enabled service accounts that have never logged on.
.DESCRIPTION
    Never-logged-on accounts may represent orphaned or misconfigured service identities.
    They also carry higher risk because they have never proven their configuration is correct.
.PARAMETER Base  AD search base (OU or domain DN).
#>
function Test-NeverLoggedOn {
    param([string]$Base)
    Write-Sub "Never-Logged-On Service Accounts"
    try {
        $never = Get-ADUser -SearchBase $Base `
                     -Filter { LastLogonDate -notlike "*" -and Enabled -eq $true } `
                     -Properties LastLogonDate, Description, Created |
                 Where-Object { Test-NamingConvention $_.SamAccountName }

        if ($never) {
            Write-Warn "$($never.Count) account(s) have never logged on:"
            Show-Paged $never @("SamAccountName", "Created", "Description")
            Write-AuditLog "TEST_NEVER_LOGON" "DOMAIN" "FAILURE" "Count=$($never.Count)"
        }
        else { Write-OK "All accounts have logged on at least once."; Write-AuditLog "TEST_NEVER_LOGON" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "Never-logged-on scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Lists Standard service accounts with PasswordNeverExpires whose password is older than N days.
.DESCRIPTION
    Even when PasswordNeverExpires is set, organisations typically require periodic password
    rotation (e.g., annually) as a compensating control. This test surfaces accounts that
    exceed the configured maximum rotation age.
.PARAMETER MaxDays  Maximum acceptable password age in days.
.PARAMETER Base     AD search base.
#>
function Test-PasswordAge {
    param([int]$MaxDays, [string]$Base)
    Write-Sub "Password Age Scan (last rotation > $MaxDays days ago)"
    $cutoff = (Get-Date).AddDays(-$MaxDays)
    try {
        $old = Get-ADUser -SearchBase $Base `
                   -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
                   -Properties PasswordLastSet, Description |
               Where-Object { Test-NamingConvention $_.SamAccountName -and $_.PasswordLastSet -lt $cutoff }

        if ($old) {
            Write-Warn "$($old.Count) account(s) have not had their password rotated in > $MaxDays days:"
            Show-Paged $old @("SamAccountName", "PasswordLastSet", "Description")
            Write-AuditLog "TEST_PWD_AGE" "DOMAIN" "FAILURE" "Count=$($old.Count)"
        }
        else { Write-OK "All accounts within password age threshold."; Write-AuditLog "TEST_PWD_AGE" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "Password age scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Checks all discovered service accounts against the configured naming convention patterns.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-NamingCompliance {
    param([hashtable]$Dom)
    Write-Sub "Naming Convention Compliance"
    Write-Info "Active patterns: $($CFG.NamingPatterns -join '  |  ')"
    try {
        $inv        = Get-AllServiceAccounts $Dom
        $violations = $inv | Where-Object { -not (Test-NamingConvention $_.SamAccountName) }

        if ($violations) {
            Write-Warn "$($violations.Count) naming violation(s) found:"
            Show-Paged $violations @("Type", "SamAccountName", "OU")
            Write-AuditLog "TEST_NAMING" "DOMAIN" "FAILURE" "Count=$($violations.Count)"
        }
        else { Write-OK "All accounts comply with naming conventions."; Write-AuditLog "TEST_NAMING" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "Naming compliance check failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Retrieves and displays Enabled, LockedOut, PasswordExpired, and LastLogon for all accounts in an OU.
.PARAMETER OU  Distinguished Name of the OU to report on.
#>
function Test-BulkStatus {
    param([string]$OU)
    Write-Sub "Bulk Status Report: $OU"
    try {
        # Standard user accounts
        $users = Get-ADUser -SearchBase $OU -Filter * -Properties Enabled, LockedOut, PasswordExpired, LastLogonDate |
                 Select-Object @{ N="Type"; E={"Standard"} }, SamAccountName, Enabled, LockedOut, PasswordExpired, LastLogonDate

        # MSA and gMSA accounts (managed password — no expiry concept)
        $svcAccts = Get-ADServiceAccount -SearchBase $OU -Filter * -Properties Enabled, ObjectClass |
                    Select-Object @{ N="Type"; E={ if ($_.ObjectClass -eq "msDS-GroupManagedServiceAccount") { "gMSA" } else { "MSA" } } },
                                  SamAccountName, Enabled,
                                  @{ N="LockedOut"; E={"N/A"} },
                                  @{ N="PasswordExpired"; E={"Auto-managed"} },
                                  @{ N="LastLogonDate"; E={"N/A"} }

        $combined = @($users) + @($svcAccts)
        if ($combined) {
            Show-Paged $combined @("Type", "SamAccountName", "Enabled", "LockedOut", "PasswordExpired", "LastLogonDate")
        }
        else { Write-Info "No accounts found in the specified OU." }
    }
    catch { Write-Fail "Bulk status check failed: $($_.Exception.Message)" }
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECURITY MODULE — Attack surface and hardening checks
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS  Entry point for the Security submenu.
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-SecurityMenu {
    param([hashtable]$Dom)
    Write-Header "SECURITY HARDENING CHECKS" Red
    $choice = Read-Choice "Select a security check:" @(
        "Kerberoastable accounts        (SPNs + weak encryption)",
        "AS-REP Roastable accounts      (no pre-authentication required)",
        "Domain-wide delegation sweep   (unconstrained + constrained)",
        "PASSWD_NOTREQD flag scan",
        "Reversible password encryption scan",
        "Shadow Admin detection         (adminCount=1, not in priv groups)",
        "SID History scan               (legacy domain privileges)",
        "Weak Kerberos encryption       (DES / RC4)",
        "Logon workstation restriction audit",
        "ACL audit on a specific account object",
        "AdminSDHolder ACL comparison   (backdoor ACE detection)",
        "Protected Users group impact check",
        "Credential Guard compatibility check",
        "Full security sweep            (all checks + optional email)",
        "← Back"
    ) 0 Red

    switch ($choice) {
        0  { Test-Kerberoastable       $Dom }
        1  { Test-ASREPRoastable       $Dom }
        2  { Test-DelegationSweep      $Dom }
        3  { Test-PASSWDNotReqd        $Dom }
        4  { Test-ReversibleEncryption $Dom }
        5  { Test-ShadowAdmins         $Dom }
        6  { Test-SIDHistory           $Dom }
        7  { Test-WeakKerberosEncryption $Dom }
        8  { Test-LogonWorkstationAudit  $Dom }
        9  { Test-AccountACL (Read-SAMName "SAM Account Name") }
        10 { Test-AdminSDHolder        $Dom }
        11 { Test-ProtectedUsersCheck  $Dom }
        12 { Test-CredentialGuardCompat $Dom }
        13 {
            Write-Sub "Running Full Security Sweep — all checks"
            Test-Kerberoastable $Dom;      Test-ASREPRoastable $Dom
            Test-DelegationSweep $Dom;     Test-PASSWDNotReqd $Dom
            Test-ReversibleEncryption $Dom; Test-ShadowAdmins $Dom
            Test-SIDHistory $Dom;          Test-WeakKerberosEncryption $Dom
            Test-AdminSDHolder $Dom;       Test-CredentialGuardCompat $Dom
            Test-ProtectedUsersCheck $Dom

            if ($SmtpAlert -or (Confirm-Action "Email security sweep summary?")) {
                Send-AlertEmail `
                    "AD Security Sweep — $($Dom.FQDN) — $(Get-Date -Format 'yyyy-MM-dd')" `
                    "<p>Full security sweep completed. Review the audit log for all findings.</p>"
            }
        }
        14 { return }
    }
    Pause-Screen
}

<#
.SYNOPSIS
    Identifies accounts that are vulnerable to Kerberoasting.
.DESCRIPTION
    Kerberoasting is an offline password cracking attack: any authenticated domain user
    can request a Kerberos service ticket (TGS) for any account with an SPN. The ticket
    is encrypted with the account's password hash and can be cracked offline.
    Risk is highest for accounts with weak/RC4 encryption and privileged access.
    Mitigation: Set AES256 encryption type and rotate to long random passwords.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-Kerberoastable {
    param([hashtable]$Dom)
    Write-Sub "Kerberoastable Accounts (have SPNs — vulnerable to offline ticket cracking)"
    try {
        $accounts = Get-ADUser -SearchBase $Dom.DN `
                       -Filter { ServicePrincipalName -like "*" -and Enabled -eq $true } `
                       -Properties ServicePrincipalName, PasswordLastSet, KerberosEncryptionType, adminCount |
                   Where-Object { $_.SamAccountName -ne "krbtgt" }  # krbtgt is expected to have SPNs

        if (-not $accounts) { Write-OK "No Kerberoastable accounts found."; return }

        Write-Warn "$($accounts.Count) Kerberoastable account(s) — prioritise remediation by risk:"
        foreach ($acct in $accounts) {
            # Risk-tier the finding for prioritisation
            $risk = if    ($acct.adminCount -eq 1)   { "🔴 CRITICAL (has adminCount=1 — privileged)" }
                    elseif($acct.KerberosEncryptionType -match "RC4|DES" -or -not $acct.KerberosEncryptionType) { "🟠 HIGH (RC4/DES encryption — fast to crack)" }
                    else                              { "🟡 Medium (AES — slow to crack)" }

            $encDisplay = Get-Coalesce $acct.KerberosEncryptionType "Default (implicit RC4)"
            Write-Host ("  {0,-30} Risk: {1}" -f $acct.SamAccountName, $risk) -ForegroundColor Yellow
            Write-Host ("     Enc: {0,-30} PwdLastSet: {1}" -f $encDisplay, $acct.PasswordLastSet) -ForegroundColor Gray
        }
        Write-Warn "Mitigation: Set-ADUser <account> -KerberosEncryptionType AES256"
        Write-Warn "And ensure passwords are long (25+ chars) random strings stored in a vault."
        Write-AuditLog "SEC_KERBEROAST" "DOMAIN" "FAILURE" "Count=$($accounts.Count)"
    }
    catch { Write-Fail "Kerberoastable scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Identifies accounts vulnerable to AS-REP Roasting.
.DESCRIPTION
    AS-REP Roasting exploits accounts with "Do not require Kerberos pre-authentication"
    set. An attacker WITHOUT any credentials can request an AS-REP for these accounts
    and receive a response encrypted with the account's hash — fully offline-crackable.
    This is more dangerous than Kerberoasting as no initial credentials are required.
    Fix: Set-ADUser <account> -KerberosPreAuthenticationNotRequired $false
.PARAMETER Dom  Domain info hashtable.
#>
function Test-ASREPRoastable {
    param([hashtable]$Dom)
    Write-Sub "AS-REP Roastable Accounts (no pre-auth — exploitable WITHOUT credentials)"
    try {
        $accounts = Get-ADUser -SearchBase $Dom.DN `
                       -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } `
                       -Properties DoesNotRequirePreAuth, PasswordLastSet, adminCount

        if (-not $accounts) { Write-OK "No AS-REP Roastable accounts found."; return }

        Write-Fail "$($accounts.Count) account(s) exploitable WITHOUT initial credentials:"
        $accounts | ForEach-Object {
            $risk = if ($_.adminCount -eq 1) { "🔴 CRITICAL" } else { "🟠 HIGH" }
            Write-Fail ("  {0,-30} PwdSet: {1,-25} Risk: {2}" -f $_.SamAccountName, $_.PasswordLastSet, $risk)
        }
        Write-Warn "Fix immediately: Set-ADUser <account> -KerberosPreAuthenticationNotRequired `$false"
        Write-AuditLog "SEC_ASREP" "DOMAIN" "FAILURE" "Count=$($accounts.Count)"
    }
    catch { Write-Fail "AS-REP scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Sweeps the entire domain for users and computers with unconstrained or constrained delegation.
.DESCRIPTION
    Unconstrained delegation on non-DC machines is a critical finding. Any account that
    authenticates to a service running under an unconstrained delegation account exposes
    its Kerberos TGT, which can then be used to impersonate that user to ANY service.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-DelegationSweep {
    param([hashtable]$Dom)
    Write-Sub "Domain-wide Kerberos Delegation Sweep"
    try {
        # Users with unconstrained delegation (not DCs — those are expected)
        $usersUncon  = Get-ADUser     -SearchBase $Dom.DN -Filter { TrustedForDelegation -eq $true -and Enabled -eq $true }
        $compsUncon  = Get-ADComputer -SearchBase $Dom.DN -Filter { TrustedForDelegation -eq $true -and Enabled -eq $true }
        $constrained = Get-ADUser     -SearchBase $Dom.DN `
                           -Filter { TrustedToAuthForDelegation -eq $true } `
                           -Properties TrustedToAuthForDelegation, "msDS-AllowedToDelegateTo"

        Write-Sub "Unconstrained Delegation — User Accounts"
        if ($usersUncon) {
            Write-Fail "$($usersUncon.Count) user account(s) with unconstrained delegation:"
            $usersUncon | ForEach-Object { Write-Fail "  · $($_.SamAccountName)" }
            Write-AuditLog "SEC_DELEG_UNCONSTRAINED" "DOMAIN" "FAILURE" "Users=$($usersUncon.Count)"
        }
        else { Write-OK "No user accounts with unconstrained delegation." }

        Write-Sub "Unconstrained Delegation — Non-DC Computer Accounts"
        $dcNames = (Get-ADDomainController -Filter *).Name
        $nonDCuncon = $compsUncon | Where-Object { $_.Name -notin $dcNames }
        if ($nonDCuncon) {
            Write-Fail "$($nonDCuncon.Count) non-DC computer(s) with unconstrained delegation:"
            $nonDCuncon | ForEach-Object { Write-Fail "  · $($_.Name)" }
        }
        else { Write-OK "Unconstrained delegation on computers limited to DCs (expected)." }

        Write-Sub "Constrained Delegation (Protocol Transition)"
        if ($constrained) {
            Write-Warn "$($constrained.Count) account(s) using constrained delegation (review targets):"
            $constrained | ForEach-Object {
                Write-Host "  · $($_.SamAccountName)" -ForegroundColor Yellow
                $_."msDS-AllowedToDelegateTo" | ForEach-Object { Write-Host "      → $_" -ForegroundColor Gray }
            }
        }
        else { Write-OK "No accounts with constrained delegation." }
    }
    catch { Write-Fail "Delegation sweep failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Finds accounts with the PASSWD_NOTREQD flag set, allowing empty passwords.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-PASSWDNotReqd {
    param([hashtable]$Dom)
    Write-Sub "PASSWD_NOTREQD Flag Scan"
    try {
        $accounts = Get-ADUser -SearchBase $Dom.DN `
                       -Filter { PasswordNotRequired -eq $true } `
                       -Properties PasswordNotRequired, Enabled, PasswordLastSet

        if ($accounts) {
            Write-Fail "$($accounts.Count) account(s) with PASSWD_NOTREQD (blank password may be accepted):"
            $accounts | Format-Table SamAccountName, Enabled, PasswordLastSet -AutoSize
            Write-Warn "Fix: Set-ADUser <account> -PasswordNotRequired `$false"
            Write-AuditLog "SEC_PASSWD_NOTREQD" "DOMAIN" "FAILURE" "Count=$($accounts.Count)"
        }
        else { Write-OK "No accounts have PASSWD_NOTREQD set."; Write-AuditLog "SEC_PASSWD_NOTREQD" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "PASSWD_NOTREQD scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Finds accounts storing passwords with reversible encryption (effectively plaintext).
.PARAMETER Dom  Domain info hashtable.
#>
function Test-ReversibleEncryption {
    param([hashtable]$Dom)
    Write-Sub "Reversible Password Encryption Scan"
    try {
        $accounts = Get-ADUser -SearchBase $Dom.DN `
                       -Filter { AllowReversiblePasswordEncryption -eq $true } `
                       -Properties AllowReversiblePasswordEncryption, Enabled

        if ($accounts) {
            Write-Fail "$($accounts.Count) account(s) storing passwords with reversible encryption:"
            $accounts | Format-Table SamAccountName, Enabled -AutoSize
            Write-Warn "Fix: Set-ADUser <account> -AllowReversiblePasswordEncryption `$false"
            Write-AuditLog "SEC_REVERSIBLE_ENC" "DOMAIN" "FAILURE" "Count=$($accounts.Count)"
        }
        else { Write-OK "No accounts using reversible encryption."; Write-AuditLog "SEC_REVERSIBLE_ENC" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "Reversible encryption scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Finds accounts with adminCount=1 that are NOT current members of any privileged group.
.DESCRIPTION
    When SDProp runs (every 60 minutes by default), it stamps adminCount=1 on members
    of protected groups and applies the AdminSDHolder ACL. If an account is subsequently
    removed from the group, adminCount is NOT automatically cleared — the account retains
    the elevated ACL indefinitely. These are called "shadow admins."
    A shadow admin has all the ACL privileges of a Domain Admin but does not show up in
    standard privileged group membership reports.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-ShadowAdmins {
    param([hashtable]$Dom)
    Write-Sub "Shadow Admin Detection (adminCount=1 but not in any privileged group)"
    try {
        # Build the current union of all privileged group members
        $currentPrivMembers = @()
        foreach ($group in $CFG.AdminGroups) {
            try {
                $currentPrivMembers += (Get-ADGroupMember $group -Recursive -EA SilentlyContinue).SamAccountName
            }
            catch {}
        }
        $currentPrivMembers = $currentPrivMembers | Sort-Object -Unique

        # Any account with adminCount=1 that is NOT in the current privileged set is a shadow admin
        $allAdminCount = Get-ADUser -SearchBase $Dom.DN `
                             -Filter { adminCount -eq 1 } `
                             -Properties adminCount, LastLogonDate, Enabled

        $shadows = $allAdminCount | Where-Object { $_.SamAccountName -notin $currentPrivMembers }

        if ($shadows) {
            Write-Fail "$($shadows.Count) SHADOW ADMIN(S) detected — retained privileged ACLs without group membership:"
            $shadows | Format-Table SamAccountName, Enabled, LastLogonDate -AutoSize
            Write-Warn "Mitigation: Set-ADUser <account> -Clear adminCount  (then SDProp will reset ACLs after its next run)"
            Write-AuditLog "SEC_SHADOW_ADMIN" "DOMAIN" "FAILURE" "Count=$($shadows.Count)"
        }
        else {
            Write-OK "No shadow admins detected."
            Write-AuditLog "SEC_SHADOW_ADMIN" "DOMAIN" "SUCCESS" ""
        }
    }
    catch { Write-Fail "Shadow admin scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Finds service accounts carrying SID History from a previous domain.
.DESCRIPTION
    SID History allows migrated accounts to access resources in the old domain.
    If the source domain is decommissioned or the migration is complete, SID History
    represents hidden privilege escalation paths and should be removed.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-SIDHistory {
    param([hashtable]$Dom)
    Write-Sub "SID History Scan"
    try {
        $accounts = Get-ADUser -SearchBase $Dom.DN -Filter { SIDHistory -like "*" } `
                       -Properties SIDHistory, Enabled, LastLogonDate |
                   Where-Object { Test-NamingConvention $_.SamAccountName }

        if ($accounts) {
            Write-Fail "$($accounts.Count) service account(s) with SID History (potential hidden privileges):"
            $accounts | ForEach-Object {
                Write-Fail ("  {0,-30} Legacy SIDs: {1}" -f $_.SamAccountName, @($_.SIDHistory).Count)
                $_.SIDHistory | ForEach-Object { Write-Host "    → $($_.Value)" -ForegroundColor Gray }
            }
            Write-Warn "Remove SID History if the source domain is decommissioned."
            Write-AuditLog "SEC_SID_HISTORY" "DOMAIN" "FAILURE" "Count=$($accounts.Count)"
        }
        else { Write-OK "No SID History found on service accounts."; Write-AuditLog "SEC_SID_HISTORY" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "SID History scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Identifies accounts using weak DES or RC4 Kerberos encryption.
.DESCRIPTION
    DES has been broken for decades. RC4-HMAC is still common but has known
    weaknesses (e.g., it enables Kerberoasting) and is deprecated in Windows 11/2022.
    All service accounts should use AES256 exclusively.
    Note: accounts with NO explicit encryption type set default to RC4 for backwards
    compatibility — this is equally risky.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-WeakKerberosEncryption {
    param([hashtable]$Dom)
    Write-Sub "Weak Kerberos Encryption Scan (DES / RC4)"
    try {
        # Accounts with explicitly configured weak encryption
        $explicitWeak = Get-ADUser -SearchBase $Dom.DN -Filter { Enabled -eq $true } `
                            -Properties KerberosEncryptionType, ServicePrincipalName |
                        Where-Object {
                            $_.KerberosEncryptionType -and
                            ($_.KerberosEncryptionType -match "DES|RC4") -and
                            $_.KerberosEncryptionType -notmatch "AES"
                        }

        # SPN-bearing accounts with NO explicit encryption type (defaults to RC4)
        $implicitRC4  = Get-ADUser -SearchBase $Dom.DN `
                            -Filter { ServicePrincipalName -like "*" -and Enabled -eq $true } `
                            -Properties KerberosEncryptionType |
                        Where-Object {
                            (-not $_.KerberosEncryptionType -or $_.KerberosEncryptionType -eq 0) -and
                            (Test-NamingConvention $_.SamAccountName)
                        }

        if ($explicitWeak) {
            Write-Fail "$($explicitWeak.Count) account(s) with explicit weak encryption:"
            $explicitWeak | Format-Table SamAccountName, KerberosEncryptionType -AutoSize
            Write-AuditLog "SEC_WEAK_KERB" "DOMAIN" "FAILURE" "Explicit=$($explicitWeak.Count)"
        }
        else { Write-OK "No accounts with explicit weak encryption types." }

        if ($implicitRC4) {
            Write-Warn "$($implicitRC4.Count) SPN-bearing account(s) with no encryption type set (implicit RC4):"
            $implicitRC4 | Format-Table SamAccountName -AutoSize
            Write-AuditLog "SEC_WEAK_KERB" "DOMAIN" "FAILURE" "ImplicitRC4=$($implicitRC4.Count)"
        }
        else { Write-OK "No SPN accounts relying on implicit RC4." }

        if ($explicitWeak -or $implicitRC4) {
            Write-Warn "Mitigation: Set-ADUser <account> -KerberosEncryptionType AES256"
        }
    }
    catch { Write-Fail "Weak Kerberos encryption scan failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Audits which service accounts have no workstation logon restriction.
.DESCRIPTION
    Restricting service accounts to log on only from specific machines limits lateral
    movement if credentials are compromised. Unrestricted accounts can authenticate
    from any workstation in the domain.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-LogonWorkstationAudit {
    param([hashtable]$Dom)
    Write-Sub "Logon Workstation Restriction Audit"
    try {
        $unrestricted = Get-ADUser -SearchBase $Dom.DN -Filter { Enabled -eq $true } `
                            -Properties LogonWorkstations |
                        Where-Object { (Test-NamingConvention $_.SamAccountName) -and (-not $_.LogonWorkstations) }

        if ($unrestricted) {
            Write-Warn "$($unrestricted.Count) service account(s) have no workstation restriction:"
            $unrestricted | Format-Table SamAccountName -AutoSize
            Write-Warn "Consider restricting accounts to specific servers using Manage → Logon workstation restriction."
            Write-AuditLog "SEC_LOGON_WS" "DOMAIN" "FAILURE" "Count=$($unrestricted.Count)"
        }
        else { Write-OK "All service accounts have logon workstation restrictions."; Write-AuditLog "SEC_LOGON_WS" "DOMAIN" "SUCCESS" "" }
    }
    catch { Write-Fail "Logon workstation audit failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Audits the ACL on a specific account's AD object for unexpected write permissions.
.DESCRIPTION
    Any identity with GenericAll, WriteDACL, WriteOwner, GenericWrite, ResetPassword,
    or WriteProperty on an account object can effectively take control of that account
    — change its password, add it to groups, or modify its attributes.
    This check surfaces non-standard ACEs that should be reviewed.
.PARAMETER Sam  SAM Account Name to audit.
#>
function Test-AccountACL {
    param([string]$Sam)
    Write-Sub "ACL Audit: $Sam"
    Write-Info "Checking for non-standard write permissions on this account's AD object..."
    try {
        $type = Resolve-AccountType $Sam
        $dn   = if ($type -eq "Standard") { (Get-ADUser $Sam).DistinguishedName }
                else                      { (Get-ADServiceAccount $Sam).DistinguishedName }

        $acl      = Get-Acl "AD:\$dn"
        $riskyAce = $acl.Access | Where-Object {
            $_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner|GenericWrite|ResetPassword|WriteProperty" -and
            $_.AccessControlType     -eq "Allow" -and
            # Filter out expected trustees — customise this list for your environment
            $_.IdentityReference     -notmatch "^(NT AUTHORITY|BUILTIN|Domain Admins|Account Operators|$env:USERDOMAIN\\Administrator)"
        }

        if ($riskyAce) {
            Write-Fail "$($riskyAce.Count) unexpected ACE(s) grant write access to '$Sam':"
            $riskyAce | ForEach-Object {
                Write-Warn ("  {0,-45} → {1}" -f $_.IdentityReference, $_.ActiveDirectoryRights)
            }
            Write-Crit "Any identity listed above can effectively control '$Sam' (password reset, group add, attribute modification)."
            Write-AuditLog "SEC_ACL_AUDIT" $Sam "FAILURE" "RiskyACEs=$($riskyAce.Count)"
        }
        else { Write-OK "No unexpected write permissions found on '$Sam'."; Write-AuditLog "SEC_ACL_AUDIT" $Sam "SUCCESS" "" }

        # Also report the object owner — non-admin owners are unusual
        $owner = $acl.Owner
        Write-Info "Object owner: $owner"
        if ($owner -notmatch "Domain Admins|Administrators") {
            Write-Warn "Object is not owned by Domain Admins or Administrators — investigate."
        }
    }
    catch { Write-Fail "ACL audit failed (requires AD read permissions): $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Compares ACLs on adminCount=1 accounts against the AdminSDHolder template ACL.
.DESCRIPTION
    SDProp resets ACLs on adminCount=1 objects every 60 minutes to match AdminSDHolder.
    Extra ACEs on these objects (not present in AdminSDHolder) survive SDProp resets only
    if they are added AFTER SDProp runs and BEFORE the next run — this is a classic
    persistence/backdoor technique. Any extra ACEs found here should be investigated.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-AdminSDHolder {
    param([hashtable]$Dom)
    Write-Sub "AdminSDHolder ACL Comparison (backdoor ACE detection)"
    Write-Info "Extra ACEs on adminCount=1 accounts not present in AdminSDHolder may indicate backdoors."
    try {
        # Retrieve the AdminSDHolder template ACL
        $sdHolderAcl = (Get-Acl "AD:\CN=AdminSDHolder,CN=System,$($Dom.DN)").Access |
                       Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType

        $protectedAccts = Get-ADUser -SearchBase $Dom.DN -Filter { adminCount -eq 1 } -Properties DistinguishedName
        $backdoorCount  = 0

        foreach ($acct in $protectedAccts) {
            $objAcl    = (Get-Acl "AD:\$($acct.DistinguishedName)").Access |
                         Where-Object { $_.AccessControlType -eq "Allow" } |
                         Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType

            # Find ACEs present on the object but NOT in AdminSDHolder
            $extraAces = $objAcl | Where-Object {
                $candidate = $_
                -not ($sdHolderAcl | Where-Object {
                    $_.IdentityReference    -eq $candidate.IdentityReference -and
                    $_.ActiveDirectoryRights -eq $candidate.ActiveDirectoryRights
                })
            }

            if ($extraAces) {
                Write-Warn "  $($acct.SamAccountName) — $($extraAces.Count) extra ACE(s) not in AdminSDHolder:"
                $extraAces | ForEach-Object {
                    Write-Host "    → $($_.IdentityReference): $($_.ActiveDirectoryRights)" -ForegroundColor Red
                }
                $backdoorCount++
            }
        }

        if ($backdoorCount -eq 0) { Write-OK "No ACL differences from AdminSDHolder detected." }
        else                      { Write-Fail "$backdoorCount account(s) have extra ACEs — investigate immediately!" }

        Write-AuditLog "SEC_ADMINSD_HOLDER" "DOMAIN" (if ($backdoorCount) { "FAILURE" } else { "SUCCESS" }) "Backdoors=$backdoorCount"
    }
    catch { Write-Fail "AdminSDHolder comparison failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS  Identifies service accounts incompatible with Windows Credential Guard.
.DESCRIPTION
    Credential Guard blocks NTLM, RC4-only Kerberos, and unconstrained delegation.
    If Credential Guard is deployed (or planned), accounts with these settings will
    cause service authentication failures.
.PARAMETER Dom  Domain info hashtable.
#>
function Test-CredentialGuardCompat {
    param([hashtable]$Dom)
    Write-Sub "Credential Guard Compatibility Check"
    Write-Info "Credential Guard blocks: NTLM, RC4-only Kerberos, unconstrained delegation."
    try {
        $accounts = Get-ADUser -SearchBase $Dom.DN -Filter { Enabled -eq $true } `
                       -Properties TrustedForDelegation, KerberosEncryptionType |
                   Where-Object { Test-NamingConvention $_.SamAccountName }

        $issueCount = 0
        foreach ($acct in $accounts) {
            $problems = @()
            if ($acct.TrustedForDelegation) { $problems += "UnconstrainedDelegation" }
            if ($acct.KerberosEncryptionType -and
                $acct.KerberosEncryptionType -match "RC4|DES" -and
                $acct.KerberosEncryptionType -notmatch "AES") {
                $problems += "RC4orDESOnly"
            }
            if ($problems) {
                Write-Warn ("  {0,-30} → {1}" -f $acct.SamAccountName, ($problems -join ", "))
                $issueCount++
            }
        }
        if ($issueCount -eq 0) { Write-OK "All service accounts are Credential Guard compatible." }
        else                   { Write-Fail "$issueCount account(s) are NOT Credential Guard compatible." }
        Write-AuditLog "SEC_CREDGUARD" "DOMAIN" (if ($issueCount) { "FAILURE" } else { "SUCCESS" }) "Issues=$issueCount"
    }
    catch { Write-Fail "Credential Guard check failed: $($_.Exception.Message)" }
}

# ══════════════════════════════════════════════════════════════════════════════
#  VIRTUAL ACCOUNTS MODULE — NT SERVICE\* and built-in identity discovery
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Discovers virtual accounts and built-in service identities on Windows hosts.
.DESCRIPTION
    Virtual accounts (NT SERVICE\<ServiceName>) are per-service local identities
    introduced in Windows Server 2008 R2. They are not AD objects — they exist only
    on the local machine and automatically get network identity via the machine account.
    This function scans one or more hosts and categorises all found service identities.
    NOTE: Uses Get-WmiObject which is available in PowerShell 5.1. In PowerShell 7+,
    use Get-CimInstance instead for improved performance and WS-Man compatibility.
.NOTES
    Virtual accounts:  Isolated, minimal-privilege, automatic password management.
    SYSTEM:            Full local admin — review all auto-start services.
    LocalService:      Network access as anonymous; minimal local rights.
    NetworkService:    Network access as machine account; minimal local rights.
#>
function Invoke-VirtualAccountMenu {
    Write-Header "VIRTUAL & BUILT-IN ACCOUNT DISCOVERY"
    Write-Info "Scans Windows hosts for NT SERVICE\*, SYSTEM, LocalService, and NetworkService."
    Write-Info "Virtual accounts are NOT AD objects — they exist only on the local host."

    $raw     = Read-Host "  Computers to scan (comma-separated; ENTER = localhost only)"
    $targets = if ($raw) { $raw -split "\s*,\s*" | Where-Object { $_ } } else { @($env:COMPUTERNAME) }

    $filter = Read-Choice "Filter results to:" @(
        "All virtual and built-in identities",
        "NT SERVICE\\* only (virtual accounts)",
        "SYSTEM / LocalService / NetworkService only",
        "Compare NT SERVICE\\* against an expected baseline"
    )

    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($target in $targets) {
        Write-Step "Scanning: $target"
        try {
            # NOTE: Get-WmiObject is used here for PS 5.1 compatibility.
            # In PS 7+, replace with: Get-CimInstance -ClassName Win32_Service -ComputerName $target
            $services = Get-WmiObject Win32_Service -ComputerName $target -EA Stop |
                        Select-Object Name, DisplayName, StartName, State, StartMode

            foreach ($svc in $services) {
                # Classify the identity type
                $vtype = switch -Regex ($svc.StartName) {
                    "^NT SERVICE\\"                   { "VirtualAccount"   }
                    "^LocalSystem$|^SYSTEM$"           { "SYSTEM"           }
                    "^NT AUTHORITY\\LocalService$"     { "LocalService"     }
                    "^NT AUTHORITY\\NetworkService$"   { "NetworkService"   }
                    default                            { $null              }
                }

                # Apply the chosen filter
                $include = switch ($filter) {
                    0 { $null -ne $vtype }
                    1 { $vtype -eq "VirtualAccount" }
                    2 { $vtype -in @("SYSTEM", "LocalService", "NetworkService") }
                    3 { $vtype -eq "VirtualAccount" }
                }

                if ($include -and $vtype) {
                    $allResults.Add([PSCustomObject]@{
                        Computer    = $target
                        ServiceName = $svc.Name
                        DisplayName = $svc.DisplayName
                        Identity    = $svc.StartName
                        Type        = $vtype
                        State       = $svc.State
                        StartMode   = $svc.StartMode
                    })
                }
            }
            Write-OK "  $target: $($allResults.Where({ $_.Computer -eq $target }).Count) matching services found."
        }
        catch { Write-Warn "  Scan failed on $target: $($_.Exception.Message)" }
    }

    if ($allResults.Count -eq 0) { Write-Info "No matching service identities found."; Pause-Screen; return }

    Write-Sub "Results ($($allResults.Count) entries)"
    Show-Paged $allResults @("Computer", "Type", "Identity", "ServiceName", "State", "StartMode")

    # Baseline comparison mode
    if ($filter -eq 3) {
        Write-Sub "Baseline Comparison"
        $expectedRaw = Read-Host "  Expected NT SERVICE accounts (comma-separated)"
        $expected    = $expectedRaw -split "\s*,\s*" | Where-Object { $_ }
        $unexpected  = $allResults | Where-Object { $_.Type -eq "VirtualAccount" -and $expected -notcontains $_.Identity }
        if ($unexpected) {
            Write-Fail "$($unexpected.Count) unexpected virtual account(s) found:"
            $unexpected | Format-Table Computer, Identity, ServiceName -AutoSize
            Write-AuditLog "VIRTUAL_BASELINE" "HOSTS" "FAILURE" "Unexpected=$($unexpected.Count)"
        }
        else { Write-OK "All virtual accounts match the expected baseline." }
    }

    # Highlight SYSTEM auto-start services for least-privilege review
    $systemAutoStart = $allResults | Where-Object { $_.Type -eq "SYSTEM" -and $_.StartMode -eq "Auto" }
    if ($systemAutoStart) {
        Write-Warn "$($systemAutoStart.Count) auto-start SYSTEM service(s) — review for least-privilege migration:"
        $systemAutoStart | Format-Table Computer, ServiceName, DisplayName -AutoSize
    }

    if (Confirm-Action "Export results to CSV?") {
        $csvPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "VirtualAccounts_$(Get-Date -Format 'yyyyMMdd').csv"
        $allResults | Export-Csv $csvPath -NoTypeInformation
        Write-OK "Exported: $csvPath"
    }
    Write-AuditLog "VIRTUAL_SCAN" ($targets -join ",") "INFO" "Found=$($allResults.Count)"
    Pause-Screen
}

# ══════════════════════════════════════════════════════════════════════════════
#  AZURE AD / ENTRA ID MODULE — Microsoft Graph Service Principal management
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Azure AD / Entra ID Service Principal inventory and security checks.
.DESCRIPTION
    Uses the Microsoft.Graph PowerShell module to:
      - List all Service Principals with credential expiry tracking
      - Identify expired or soon-to-expire certificates and client secrets
      - Find SPs without owners (governance gap)
      - Detect SPs with high-privilege Graph API permissions
      - Export SP inventory to CSV
    Requires the Microsoft.Graph module: Install-Module Microsoft.Graph -Scope CurrentUser
    Required Graph scopes: Application.Read.All, Directory.Read.All, AppRoleAssignment.Read.All
#>
function Invoke-AzureADMenu {
    Write-Header "AZURE AD / ENTRA ID — SERVICE PRINCIPALS"

    # Verify the Microsoft.Graph module is installed before attempting anything
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Applications -EA SilentlyContinue)) {
        Write-Warn "The Microsoft.Graph module is not installed."
        Write-Info "Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
        Pause-Screen; return
    }

    try { Import-Module Microsoft.Graph.Applications, Microsoft.Graph.DirectoryObjects -EA Stop }
    catch { Write-Fail "Failed to import Microsoft.Graph modules: $($_.Exception.Message)"; Pause-Screen; return }

    Write-Step "Connecting to Microsoft Graph..."
    try {
        Connect-MgGraph `
            -Scopes "Application.Read.All","Directory.Read.All","AppRoleAssignment.Read.All" `
            -EA Stop | Out-Null
        Write-OK "Connected to Microsoft Graph."
    }
    catch { Write-Fail "Microsoft Graph authentication failed: $($_.Exception.Message)"; Pause-Screen; return }

    $choice = Read-Choice "Select an operation:" @(
        "List all Service Principals",
        "Inventory with credential expiry tracking",
        "Find expired / expiring credentials (< 30 days)",
        "Find Service Principals without owners",
        "Find Service Principals with high-privilege Graph permissions",
        "Export all SPs to CSV",
        "Disconnect from Microsoft Graph",
        "← Back"
    )

    switch ($choice) {
        0 {
            Write-Step "Fetching all Service Principals..."
            $sps = Get-MgServicePrincipal -All `
                       -Property DisplayName, AppId, ServicePrincipalType, AccountEnabled, CreatedDateTime |
                   Select-Object DisplayName, AppId, ServicePrincipalType,
                                 @{ N="Enabled"; E={ $_.AccountEnabled } }, CreatedDateTime
            Write-Info "Total Service Principals: $($sps.Count)"
            Show-Paged $sps @("DisplayName", "AppId", "ServicePrincipalType", "Enabled", "CreatedDateTime")
            Write-AuditLog "AZURE_SP_LIST" "ENTRA" "INFO" "Count=$($sps.Count)"
        }

        1 {
            Write-Step "Building Service Principal inventory with credential expiry..."
            $sps = Get-MgServicePrincipal -All -Property DisplayName, AppId, ServicePrincipalType, KeyCredentials, PasswordCredentials
            $inventory = $sps | ForEach-Object {
                $sp       = $_
                $certs    = @($sp.KeyCredentials)
                $secrets  = @($sp.PasswordCredentials)
                # Find the next expiry across all credentials
                $nextExp  = (@($certs) + @($secrets)) | Where-Object { $_.EndDateTime } |
                            Sort-Object EndDateTime | Select-Object -First 1
                $daysLeft = if ($nextExp) { [int]($nextExp.EndDateTime - (Get-Date)).TotalDays } else { $null }

                [PSCustomObject]@{
                    DisplayName = $sp.DisplayName
                    AppId       = $sp.AppId
                    Type        = $sp.ServicePrincipalType
                    CertCount   = $certs.Count
                    SecretCount = $secrets.Count
                    NextExpiry  = if ($nextExp) { $nextExp.EndDateTime } else { "None" }
                    DaysLeft    = if ($null -ne $daysLeft) { $daysLeft } else { "∞" }
                }
            }
            Show-Paged $inventory @("DisplayName", "Type", "CertCount", "SecretCount", "NextExpiry", "DaysLeft")
            Write-AuditLog "AZURE_SP_INVENTORY" "ENTRA" "INFO" "Count=$($inventory.Count)"
        }

        2 {
            Write-Step "Finding credentials expiring within 30 days or already expired..."
            $sps      = Get-MgServicePrincipal -All -Property DisplayName, AppId, KeyCredentials, PasswordCredentials
            $expiring = @()
            foreach ($sp in $sps) {
                $allCreds = @($sp.KeyCredentials) + @($sp.PasswordCredentials)
                foreach ($cred in $allCreds) {
                    if ($cred.EndDateTime -and $cred.EndDateTime -lt (Get-Date).AddDays(30)) {
                        $credType = if ($cred.PSObject.Properties.Name -contains "KeyId") { "Certificate" } else { "Secret" }
                        $expiring += [PSCustomObject]@{
                            SP       = $sp.DisplayName
                            AppId    = $sp.AppId
                            CredType = $credType
                            Expires  = $cred.EndDateTime
                            DaysLeft = [int]($cred.EndDateTime - (Get-Date)).TotalDays
                        }
                    }
                }
            }
            if ($expiring) {
                Write-Warn "$($expiring.Count) expiring or expired credential(s):"
                Show-Paged $expiring @("SP", "CredType", "Expires", "DaysLeft")
                if ($SmtpAlert -or (Confirm-Action "Send email alert for expiring credentials?")) {
                    $body  = "<h2>Azure Service Principal Credential Expiry Alert</h2>"
                    $body += "<table border='1' style='border-collapse:collapse'><tr><th>SP</th><th>Type</th><th>Expires</th><th>Days Left</th></tr>"
                    $expiring | ForEach-Object {
                        $body += "<tr><td>$($_.SP)</td><td>$($_.CredType)</td><td>$($_.Expires)</td><td>$($_.DaysLeft)</td></tr>"
                    }
                    $body += "</table>"
                    Send-AlertEmail "Azure SP Credential Expiry Alert — $(Get-Date -Format 'yyyy-MM-dd')" $body
                }
                Write-AuditLog "AZURE_CRED_EXPIRY" "ENTRA" "FAILURE" "Expiring=$($expiring.Count)"
            }
            else { Write-OK "No credentials expiring within 30 days." }
        }

        3 {
            Write-Step "Finding Service Principals without owners..."
            $sps     = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId
            $noOwner = $sps | Where-Object {
                (Get-MgServicePrincipalOwner -ServicePrincipalId $_.Id -EA SilentlyContinue).Count -eq 0
            }
            if ($noOwner) {
                Write-Warn "$($noOwner.Count) SP(s) have no assigned owner (governance gap):"
                $noOwner | Format-Table DisplayName, AppId -AutoSize
                Write-AuditLog "AZURE_NO_OWNER" "ENTRA" "FAILURE" "Count=$($noOwner.Count)"
            }
            else { Write-OK "All Service Principals have at least one assigned owner." }
        }

        4 {
            # Check against known high-privilege Microsoft Graph permission GUIDs
            # and display names — both are checked for robustness
            Write-Step "Finding Service Principals with high-privilege Graph API permissions..."
            $highPrivilegeGUIDs = @(
                "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",  # RoleManagement.ReadWrite.Directory
                "06b708a9-e830-4db3-a914-8ddd2e08f73b",  # AppRoleAssignment.ReadWrite.All
                "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",  # Application.ReadWrite.All (delegated)
                "741f803b-c850-494e-b5df-cde7c675a1ca",  # User.ReadWrite.All
                "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",  # Application.ReadWrite.OwnedBy
                "19dbc75e-c2e2-444c-a770-ec69d8559fc7"   # Directory.ReadWrite.All
            )
            $highPrivilegeNames = @(
                "RoleManagement.ReadWrite.Directory",
                "Directory.ReadWrite.All",
                "Application.ReadWrite.All",
                "User.ReadWrite.All",
                "AppRoleAssignment.ReadWrite.All"
            )
            $sps   = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId
            $risky = @()
            foreach ($sp in $sps) {
                try {
                    $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -EA SilentlyContinue
                    foreach ($assignment in $assignments) {
                        $isHighPriv = ($highPrivilegeGUIDs -contains $assignment.AppRoleId.ToString()) -or
                                      ($highPrivilegeNames | Where-Object { $assignment.ResourceDisplayName -match $_ })
                        if ($isHighPriv) {
                            $risky += [PSCustomObject]@{
                                SP         = $sp.DisplayName
                                AppId      = $sp.AppId
                                Resource   = $assignment.ResourceDisplayName
                                AppRoleId  = $assignment.AppRoleId
                            }
                        }
                    }
                }
                catch {}
            }
            if ($risky) {
                Write-Fail "$($risky.Count) high-privilege Graph permission assignment(s) found:"
                $risky | Format-Table SP, Resource, AppRoleId -AutoSize
                Write-AuditLog "AZURE_HIGH_PERM" "ENTRA" "FAILURE" "Count=$($risky.Count)"
            }
            else { Write-OK "No high-privilege Graph API permissions detected." }
        }

        5 {
            $sps = Get-MgServicePrincipal -All `
                       -Property DisplayName, AppId, ServicePrincipalType, CreatedDateTime |
                   Select-Object DisplayName, AppId, ServicePrincipalType, CreatedDateTime
            $exportPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "AzureSP_$(Get-Date -Format 'yyyyMMdd').csv"
            $sps | Export-Csv $exportPath -NoTypeInformation
            Write-OK "Exported $($sps.Count) Service Principals to: $exportPath"
            Write-AuditLog "AZURE_SP_EXPORT" "ENTRA" "SUCCESS" "Count=$($sps.Count)"
        }

        6 {
            try { Disconnect-MgGraph | Out-Null; Write-OK "Disconnected from Microsoft Graph." }
            catch { Write-Warn "Graph disconnect error: $($_.Exception.Message)" }
        }

        7 { return }
    }
    Pause-Screen
}

# ══════════════════════════════════════════════════════════════════════════════
#  COMPUTER ACCOUNTS AS SERVICE IDENTITIES MODULE
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Audits computer accounts that may be acting as service identities.
.DESCRIPTION
    Some legacy deployments use computer accounts as service identities (registering
    non-standard SPNs or configuring delegation). These are harder to manage than
    dedicated service accounts and often overlooked in security reviews.
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-ComputerAccountServiceMenu {
    param([hashtable]$Dom)
    Write-Header "COMPUTER ACCOUNTS AS SERVICE IDENTITIES"
    Write-Info "Identifies computer accounts with non-standard SPNs, delegation, or stale service usage."

    $menuChoice = Read-Choice "Select:" @(
        "Discover computer accounts with non-standard SPNs",
        "Find computer accounts with unconstrained delegation (non-DC)",
        "Find computer accounts with constrained delegation",
        "Find stale computer-based service identities",
        "← Back"
    )

    switch ($menuChoice) {
        0 {
            Write-Step "Scanning for non-standard SPNs on computer accounts..."
            # Standard SPNs automatically registered by the OS — these are expected
            $stdPatterns = @("^HOST/","^TERMSRV/","^RestrictedKrbHost/","^WSMAN/","^RPCSS/","^GC/")

            $comps = Get-ADComputer -SearchBase $Dom.DN `
                         -Filter { ServicePrincipalName -like "*" } `
                         -Properties ServicePrincipalName, Enabled, LastLogonDate, Description

            # NOTE: Using $comp (not $c) to avoid shadowing the outer $menuChoice variable
            $nonStandard = $comps | Where-Object {
                $comp = $_
                $comp.ServicePrincipalName | Where-Object {
                    $spn = $_
                    -not ($stdPatterns | Where-Object { $spn -match $_ })
                }
            }

            if ($nonStandard) {
                Write-Warn "$($nonStandard.Count) computer account(s) with non-standard SPNs:"
                $nonStandard | ForEach-Object {
                    Write-Host "  · $($_.Name)" -ForegroundColor Yellow
                    $_.ServicePrincipalName | Where-Object {
                        $spn = $_; -not ($stdPatterns | Where-Object { $spn -match $_ })
                    } | ForEach-Object { Write-Host "      SPN: $_" -ForegroundColor Gray }
                }
                Write-AuditLog "COMP_NONSTANDARD_SPN" "DOMAIN" "FAILURE" "Count=$($nonStandard.Count)"
            }
            else { Write-OK "No non-standard SPNs found on computer accounts." }
        }

        1 {
            $comps   = Get-ADComputer -SearchBase $Dom.DN `
                           -Filter { TrustedForDelegation -eq $true -and Enabled -eq $true } `
                           -Properties TrustedForDelegation, LastLogonDate
            $dcNames = (Get-ADDomainController -Filter *).Name
            $nonDC   = $comps | Where-Object { $_.Name -notin $dcNames }

            if ($nonDC) {
                Write-Fail "$($nonDC.Count) non-DC computer(s) with unconstrained delegation (HIGH RISK):"
                $nonDC | Format-Table Name, LastLogonDate -AutoSize
                Write-AuditLog "COMP_UNCONSTRAINED" "DOMAIN" "FAILURE" "Count=$($nonDC.Count)"
            }
            else { Write-OK "Only Domain Controllers have unconstrained delegation (expected)." }
        }

        2 {
            $comps = Get-ADComputer -SearchBase $Dom.DN `
                         -Filter { TrustedToAuthForDelegation -eq $true } `
                         -Properties TrustedToAuthForDelegation, "msDS-AllowedToDelegateTo", Enabled

            if ($comps) {
                Write-Warn "$($comps.Count) computer(s) with constrained delegation — review targets:"
                $comps | ForEach-Object {
                    Write-Host "  · $($_.Name)" -ForegroundColor Yellow
                    $_."msDS-AllowedToDelegateTo" | ForEach-Object { Write-Host "      → $_" }
                }
                Write-AuditLog "COMP_CONSTRAINED" "DOMAIN" "INFO" "Count=$($comps.Count)"
            }
            else { Write-OK "No computer accounts with constrained delegation." }
        }

        3 {
            $stale = Get-ADComputer -SearchBase $Dom.DN `
                         -Filter { ServicePrincipalName -like "*" } `
                         -Properties ServicePrincipalName, Enabled, LastLogonDate |
                     Where-Object {
                         (-not $_.Enabled) -or
                         ($_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-$CFG.StaleThresholdDays))
                     }

            if ($stale) {
                Write-Warn "$($stale.Count) stale computer service identities (disabled or no recent logon):"
                $stale | Format-Table Name, Enabled, LastLogonDate -AutoSize
                Write-AuditLog "COMP_STALE_SPN" "DOMAIN" "FAILURE" "Count=$($stale.Count)"
            }
            else { Write-OK "No stale computer service identities found." }
        }

        4 { return }
    }
    Pause-Screen
}

# ══════════════════════════════════════════════════════════════════════════════
#  GROUP POLICY IMPACT MODULE — GPO analysis for service account environments
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Analyses the impact of Group Policy on service account configuration.
.DESCRIPTION
    GPOs can affect service accounts in ways that are difficult to diagnose:
      - Password complexity / age policies overriding individual account settings
      - User Rights Assignment policies blocking service logon
      - Service configuration GPO settings that embed credentials
    Requires the GroupPolicy module from RSAT (Remote Server Administration Tools).
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-GroupPolicyMenu {
    param([hashtable]$Dom)
    Write-Header "GROUP POLICY IMPACT ANALYSIS"
    $choice = Read-Choice "Select:" @(
        "Effective GPOs on a service account (gpresult HTML report)",
        "Scan GPOs for password/account policy settings",
        "Find GPOs restricting service logon rights",
        "Find GPOs that configure service log-on credentials",
        "← Back"
    )

    switch ($choice) {
        0 {
            $sam = Read-SAMName "Service account SAM name"
            if ((Resolve-AccountType $sam) -ne "Standard") {
                Write-Warn "gpresult is only applicable to Standard (user-based) accounts."
                Pause-Screen; return
            }
            Write-Step "Running gpresult for '$sam' — this may take 30–60 seconds..."
            $tempFile = [System.IO.Path]::GetTempFileName() + ".html"
            try {
                $proc = Start-Process gpresult `
                    -ArgumentList "/USER $sam /H `"$tempFile`" /F" `
                    -Wait -PassThru -NoNewWindow
                if ($proc.ExitCode -eq 0 -and (Test-Path $tempFile)) {
                    $reportPath = Join-Path $REPORT_DIR "GPO_${sam}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                    Move-Item $tempFile $reportPath -Force
                    Write-OK "GPO report saved: $reportPath"
                    if (Confirm-Action "Open report in browser?") { Start-Process $reportPath }
                    Write-AuditLog "GPO_ANALYSIS" $sam "SUCCESS" "Report=$reportPath"
                }
                else {
                    Write-Warn "gpresult exited with code $($proc.ExitCode)."
                    Write-Info "Tip: Run as Domain Admin, or on the same machine the account logs on from."
                    Write-AuditLog "GPO_ANALYSIS" $sam "FAILURE" "ExitCode=$($proc.ExitCode)"
                }
            }
            catch { Write-Fail "gpresult execution failed: $($_.Exception.Message)" }
            finally { Remove-Item $tempFile -EA SilentlyContinue }
        }

        1 {
            Write-Step "Scanning GPOs for password and account policy settings..."
            try {
                $gpos  = Get-GPO -All -Domain $Dom.FQDN
                $found = @()
                foreach ($gpo in $gpos) {
                    try {
                        [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Dom.FQDN -EA Stop
                        $pwdSettings = $report.GPO.Computer.ExtensionData |
                                       Where-Object { $_.Name -match "Password|Account" }
                        if ($pwdSettings) {
                            $found += [PSCustomObject]@{ GPOName = $gpo.DisplayName; GpoStatus = $gpo.GpoStatus }
                        }
                    }
                    catch {}
                }
                if ($found) {
                    Write-Warn "$($found.Count) GPO(s) contain password or account policy settings:"
                    $found | Format-Table GPOName, GpoStatus -AutoSize
                    Write-Info "Cross-reference these GPOs with the OUs hosting your service accounts."
                    Write-AuditLog "GPO_PWD_SCAN" "DOMAIN" "INFO" "Found=$($found.Count)"
                }
                else { Write-OK "No GPOs with explicit password/account policy overrides found." }
            }
            catch {
                Write-Warn "GPO scan requires the GroupPolicy RSAT module: $($_.Exception.Message)"
                Write-Info "Install RSAT: Add-WindowsFeature GPMC  (or via Settings → Optional Features on Windows 10/11)"
            }
        }

        2 {
            Write-Step "Scanning GPOs for logon right restrictions affecting services..."
            try {
                $gpos  = Get-GPO -All -Domain $Dom.FQDN
                $found = @()
                foreach ($gpo in $gpos) {
                    try {
                        [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Dom.FQDN -EA Stop
                        # User Rights Assignment section controls which identities can log on as a service,
                        # interactively, via network, etc. — all are relevant to service accounts.
                        $logonRights = $report.GPO.Computer.ExtensionData.Extension.UserRightsAssignment |
                                       Where-Object {
                                           $_.Name -match "SeServiceLogonRight|SeDenyServiceLogonRight|" +
                                                          "SeInteractiveLogonRight|SeDenyInteractiveLogonRight|" +
                                                          "SeNetworkLogonRight|SeDenyNetworkLogonRight"
                                       }
                        if ($logonRights) {
                            $found += [PSCustomObject]@{
                                GPOName = $gpo.DisplayName
                                Rights  = ($logonRights.Name -join " | ")
                            }
                        }
                    }
                    catch {}
                }
                if ($found) {
                    Write-Warn "$($found.Count) GPO(s) affect service/interactive logon rights:"
                    $found | Format-Table GPOName, Rights -AutoSize -Wrap
                    Write-Info "Ensure 'Log on as a service' (SeServiceLogonRight) includes your service accounts."
                    Write-AuditLog "GPO_LOGON_RIGHTS" "DOMAIN" "INFO" "Found=$($found.Count)"
                }
                else { Write-OK "No GPOs restricting service logon rights found." }
            }
            catch { Write-Warn "Requires GroupPolicy RSAT module: $($_.Exception.Message)" }
        }

        3 {
            Write-Step "Scanning GPOs that configure service credentials (embedded account/password)..."
            Write-Warn "GPO-embedded service credentials are a security risk — passwords stored in SYSVOL."
            try {
                $gpos  = Get-GPO -All -Domain $Dom.FQDN
                $found = @()
                foreach ($gpo in $gpos) {
                    try {
                        [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Dom.FQDN -EA Stop
                        # NT Service configuration GPO extensions can set the RunAs account for a Windows service
                        $svcs = $report.GPO.Computer.ExtensionData.Extension.NTService |
                                Where-Object { $_.StartName }
                        if ($svcs) {
                            $svcs | ForEach-Object {
                                $found += [PSCustomObject]@{
                                    GPOName     = $gpo.DisplayName
                                    ServiceName = $_.Name
                                    RunAs       = $_.StartName
                                }
                            }
                        }
                    }
                    catch {}
                }
                if ($found) {
                    Write-Warn "$($found.Count) GPO-managed service credential assignment(s) found:"
                    $found | Format-Table GPOName, ServiceName, RunAs -AutoSize
                    Write-Warn "Prefer gMSA over GPO-embedded credentials — gMSA eliminates stored passwords entirely."
                    Write-AuditLog "GPO_SVC_ACCOUNTS" "DOMAIN" "INFO" "Found=$($found.Count)"
                }
                else { Write-OK "No GPO-managed service account credentials found." }
            }
            catch { Write-Warn "Requires GroupPolicy RSAT module: $($_.Exception.Message)" }
        }

        4 { return }
    }
    Pause-Screen
}

# ══════════════════════════════════════════════════════════════════════════════
#  MULTI-FOREST MODULE — Cross-domain and cross-forest operations
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Entry point for cross-domain and cross-forest inventory, security, and health operations.
.DESCRIPTION
    Enumerates all domains in the current forest (and any configured trusted forests),
    then provides inventory, security scanning, and health auditing across all of them
    in a single consolidated run.
    Discovered domains are cached in $script:AllDomains for the session to avoid
    repeated forest enumeration calls.
    Trusted forests are configured via Settings → Manage trusted forests.
#>
function Invoke-MultiForestMenu {
    Write-Header "MULTI-FOREST / MULTI-DOMAIN OPERATIONS"
    $choice = Read-Choice "Select:" @(
        "Enumerate all domains in this forest",
        "Add a trusted forest to the scan list",
        "Inventory across ALL known domains",
        "Security scan across ALL known domains",
        "Health audit across ALL known domains",
        "View configured forests and trusted forests",
        "← Back"
    )

    switch ($choice) {
        0 {
            Write-Step "Enumerating all domains in the forest..."
            $rootDom = if ($Domain) { $Domain } else { "" }
            $doms    = Get-ForestDomains -RootDomain $rootDom

            # Cache for use by other multi-forest operations in this session
            $script:AllDomains = $doms

            if ($doms) {
                $doms | ForEach-Object { Write-OK "  $($_.FQDN)" }
                Write-Info "Total: $($doms.Count) domain(s) discovered and cached for this session."
                Write-AuditLog "FOREST_ENUM" "FOREST" "INFO" "Domains=$($doms.Count)"
            }
            else { Write-Info "No additional domains found beyond the current domain." }
        }

        1 {
            # Add a trusted forest FQDN — it will be included in all future forest scans
            $trustedFQDN = Read-NonEmpty "Trusted forest FQDN (e.g. partner.corp.com)"
            if ($CFG.TrustedForests -notcontains $trustedFQDN) {
                $CFG.TrustedForests += $trustedFQDN
                Save-Config
                Write-OK "Added '$trustedFQDN' to trusted forests. It will be included in future forest scans."
            }
            else { Write-Info "'$trustedFQDN' is already in the trusted forests list." }
        }

        2 {
            # Use cached domains if available; otherwise enumerate now
            $doms = if ($script:AllDomains.Count -gt 0) { $script:AllDomains }
                    else { Get-ForestDomains -RootDomain (if ($Domain) { $Domain } else { "" }) }

            $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($d in $doms) {
                Write-Sub "Inventorying: $($d.FQDN)"
                try {
                    $inv = Get-AllServiceAccounts $d
                    $inv | ForEach-Object {
                        # Tag each record with the domain it came from for cross-forest reporting
                        $_ | Add-Member -NotePropertyName "Domain" -NotePropertyValue $d.FQDN -Force
                        $allResults.Add($_)
                    }
                    Write-OK "  $($d.FQDN): $($inv.Count) account(s)"
                }
                catch { Write-Warn "  Inventory failed for $($d.FQDN): $($_.Exception.Message)" }
            }

            if ($allResults.Count -gt 0) {
                Show-Paged $allResults @("Domain", "Type", "SamAccountName", "Enabled", "SecurityFlags")
                if (Confirm-Action "Export cross-forest inventory to CSV?") {
                    $csvPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "ForestInventory_$(Get-Date -Format 'yyyyMMdd').csv"
                    $allResults | Export-Csv $csvPath -NoTypeInformation
                    Write-OK "Saved: $csvPath"
                }
                Write-AuditLog "FOREST_INVENTORY" "FOREST" "INFO" "Total=$($allResults.Count) Domains=$($doms.Count)"
            }
        }

        3 {
            $doms = if ($script:AllDomains.Count -gt 0) { $script:AllDomains }
                    else { Get-ForestDomains -RootDomain (if ($Domain) { $Domain } else { "" }) }

            foreach ($d in $doms) {
                Write-Sub "Security Scan: $($d.FQDN)"
                try {
                    # Run the five highest-priority security checks across each domain
                    Test-Kerberoastable $d
                    Test-ASREPRoastable $d
                    Test-ShadowAdmins   $d
                    Test-PASSWDNotReqd  $d
                    Test-SIDHistory     $d
                }
                catch { Write-Warn "  Scan failed for $($d.FQDN): $($_.Exception.Message)" }
            }
            Write-AuditLog "FOREST_SECURITY_SCAN" "FOREST" "INFO" "Domains=$($doms.Count)"
        }

        4 {
            $doms = if ($script:AllDomains.Count -gt 0) { $script:AllDomains }
                    else { Get-ForestDomains -RootDomain (if ($Domain) { $Domain } else { "" }) }

            $allInv = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($d in $doms) {
                try {
                    $inv = Get-AllServiceAccounts $d
                    $inv | ForEach-Object { $allInv.Add($_) }
                }
                catch { Write-Warn "  Inventory failed for $($d.FQDN): $($_.Exception.Message)" }
            }
            if ($allInv.Count -gt 0) { Show-HealthAudit $allInv }
            Write-AuditLog "FOREST_HEALTH" "FOREST" "INFO" "Total=$($allInv.Count)"
        }

        5 {
            Write-Info "Current domain      : $(if ($Domain) { $Domain } else { '(auto-detected from environment)' })"
            $cachedNames = if ($script:AllDomains.Count -gt 0) {
                ($script:AllDomains | ForEach-Object { $_.FQDN }) -join ", "
            } else { "None cached — run option 0 to enumerate" }
            Write-Info "Cached domains      : $cachedNames"
            Write-Info "Trusted forests     : $(if ($CFG.TrustedForests) { $CFG.TrustedForests -join ', ' } else { 'None configured' })"
        }

        6 { return }
    }
    Pause-Screen
}

# ══════════════════════════════════════════════════════════════════════════════
#  DEPENDENCY MODULE — Map where a service account is actually used
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Maps all dependencies (Windows services, scheduled tasks, IIS app pools) for an account.
.DESCRIPTION
    ALWAYS run this before modifying or deleting any service account.
    A service account may be:
      - The RunAs identity for one or more Windows services
      - The principal for one or more Scheduled Tasks
      - The identity for one or more IIS Application Pools
    All three are scanned on each target host. Results are displayed and can be
    exported to CSV for change-management documentation.
    Remote scans require:
      - WMI access (Windows Services)
      - WS-Man / PS Remoting (Scheduled Tasks, IIS App Pools)
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-DependencyMenu {
    param([hashtable]$Dom)
    Write-Header "DEPENDENCY MAPPING"
    Write-Warn "Always run dependency mapping BEFORE modifying or deleting any service account."

    $sam = Read-SAMName "SAM Account Name to map"
    if (-not (Resolve-AccountType $sam)) { Write-Fail "'$sam' not found in AD."; Pause-Screen; return }

    $raw     = Read-Host "  Computers to scan (comma-separated; ENTER = localhost only)"
    $targets = if ($raw) { $raw -split "\s*,\s*" | Where-Object { $_ } } else { @($env:COMPUTERNAME) }

    $scanType = Read-Choice "Scan scope:" @(
        "Windows Services only",
        "Scheduled Tasks only",
        "IIS Application Pools only",
        "All (Services + Tasks + IIS)"
    ) 3

    $allDeps = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($target in $targets) {
        Write-Step "Scanning: $target"
        if ($scanType -eq 0 -or $scanType -eq 3) {
            Get-WinServiceDeps  $sam $target $Dom | ForEach-Object { $allDeps.Add($_) }
        }
        if ($scanType -eq 1 -or $scanType -eq 3) {
            Get-SchedTaskDeps   $sam $target      | ForEach-Object { $allDeps.Add($_) }
        }
        if ($scanType -eq 2 -or $scanType -eq 3) {
            Get-IISPoolDeps     $sam $target      | ForEach-Object { $allDeps.Add($_) }
        }
    }

    if ($allDeps.Count -eq 0) {
        Write-OK "No dependencies found for '$sam' on the scanned system(s)."
        Write-Info "Note: Only scanned hosts that were specified — other hosts may still depend on this account."
    }
    else {
        Write-Sub "Dependencies Found ($($allDeps.Count) total)"
        Show-Paged $allDeps @("Computer", "DependencyType", "Name", "RunAsAccount", "Status")
        Write-Warn "Review ALL entries before making any changes to '$sam'!"

        if (Confirm-Action "Export dependency map to CSV?") {
            $csvPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "Deps_${sam}_$(Get-Date -Format 'yyyyMMdd').csv"
            $allDeps | Export-Csv $csvPath -NoTypeInformation
            Write-OK "Saved: $csvPath"
        }
    }
    Write-AuditLog "DEPENDENCY_SCAN" $sam "INFO" "Hosts=$($targets -join ',') Found=$($allDeps.Count)"
    Pause-Screen
}

<#
.SYNOPSIS  Queries Win32_Service on a remote (or local) host for a specific RunAs account.
.DESCRIPTION
    Uses WMI (Get-WmiObject) for PS 5.1 compatibility. Searches both the bare SAM name
    and the DOMAIN\SAM form to catch all variants.
    NOTE: In PowerShell 7+, replace Get-WmiObject with Get-CimInstance for better performance.
.PARAMETER Sam      SAM Account Name to search for.
.PARAMETER Computer Target computer name.
.PARAMETER Dom      Domain info hashtable (used to build DOMAIN\SAM search string).
.OUTPUTS   [PSCustomObject[]]  Dependency records.
#>
function Get-WinServiceDeps {
    param([string]$Sam, [string]$Computer, [hashtable]$Dom)
    $results = @()
    try {
        # WMI filter: match bare SAM name OR domain-qualified form
        $filter = "StartName LIKE '%$Sam%' OR StartName LIKE '%$($Dom.NetBIOS)\\$Sam%'"
        $svcs   = Get-WmiObject Win32_Service -ComputerName $Computer -Filter $filter -EA Stop
        foreach ($svc in $svcs) {
            $results += [PSCustomObject]@{
                Computer       = $Computer
                DependencyType = "WinService"
                Name           = $svc.Name
                RunAsAccount   = $svc.StartName
                Status         = $svc.State
            }
        }
    }
    catch { Write-Warn "  Windows Service scan failed on $Computer: $($_.Exception.Message)" }
    return $results
}

<#
.SYNOPSIS  Queries Scheduled Tasks on a host for a specific principal (RunAs) account.
.DESCRIPTION
    For the local machine, uses Get-ScheduledTask directly.
    For remote machines, requires WS-Man (PS Remoting). If WS-Man is unavailable the
    host is skipped with a warning rather than raising a hard error.
.PARAMETER Sam      SAM Account Name to search for.
.PARAMETER Computer Target computer name.
.OUTPUTS   [PSCustomObject[]]  Dependency records.
#>
function Get-SchedTaskDeps {
    param([string]$Sam, [string]$Computer)
    $results = @()
    try {
        if ($Computer -eq $env:COMPUTERNAME) {
            # Local machine: query directly
            $tasks = Get-ScheduledTask -EA Stop |
                     Where-Object { $_.Principal.UserId -match [regex]::Escape($Sam) }
        }
        else {
            # Remote machine: requires PS Remoting
            if (-not (Test-WSMan $Computer -EA SilentlyContinue)) {
                Write-Warn "  PS Remoting unavailable on $Computer — Scheduled Task scan skipped."
                return @()
            }
            $tasks = Invoke-Command -ComputerName $Computer -EA Stop -ScriptBlock {
                param($s)
                Get-ScheduledTask | Where-Object { $_.Principal.UserId -match [regex]::Escape($s) }
            } -ArgumentList $Sam
        }
        foreach ($task in $tasks) {
            $results += [PSCustomObject]@{
                Computer       = $Computer
                DependencyType = "SchedTask"
                Name           = "$($task.TaskPath)$($task.TaskName)"
                RunAsAccount   = $task.Principal.UserId
                Status         = $task.State
            }
        }
    }
    catch { Write-Warn "  Scheduled Task scan failed on $Computer: $($_.Exception.Message)" }
    return $results
}

<#
.SYNOPSIS  Queries IIS Application Pools on a host for a specific identity account.
.DESCRIPTION
    Requires the WebAdministration module on the target host.
    For the local machine, the module is imported directly.
    For remote machines, PS Remoting is used. If WS-Man or the WebAdministration
    module is unavailable, the host is skipped with a warning.
.PARAMETER Sam      SAM Account Name to search for.
.PARAMETER Computer Target computer name.
.OUTPUTS   [PSCustomObject[]]  Dependency records.
#>
function Get-IISPoolDeps {
    param([string]$Sam, [string]$Computer)
    $results = @()

    # Script block is defined once and reused for both local and remote execution
    $queryScript = {
        param($s)
        if (-not (Get-Module -ListAvailable WebAdministration -EA SilentlyContinue)) { return @() }
        Import-Module WebAdministration -EA SilentlyContinue
        Get-WebConfiguration "system.applicationHost/applicationPools/add" |
            Where-Object { $_.processModel.userName -match [regex]::Escape($s) } |
            Select-Object name,
                @{ N="UserName"; E={ $_.processModel.userName } },
                @{ N="State";    E={ (Get-WebAppPoolState $_.name).Value } }
    }

    try {
        $pools = if ($Computer -eq $env:COMPUTERNAME) {
            & $queryScript $Sam
        }
        else {
            if (-not (Test-WSMan $Computer -EA SilentlyContinue)) {
                Write-Warn "  PS Remoting unavailable on $Computer — IIS App Pool scan skipped."
                return @()
            }
            Invoke-Command -ComputerName $Computer -ScriptBlock $queryScript -ArgumentList $Sam -EA Stop
        }
        foreach ($pool in $pools) {
            $results += [PSCustomObject]@{
                Computer       = $Computer
                DependencyType = "IISAppPool"
                Name           = $pool.name
                RunAsAccount   = $pool.UserName
                Status         = $pool.State
            }
        }
    }
    catch { Write-Warn "  IIS App Pool scan failed on $Computer: $($_.Exception.Message)" }
    return $results
}

# ══════════════════════════════════════════════════════════════════════════════
#  INVENTORY MODULE — Discovery, health audit, and export reporting
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS  Entry point for the Inventory submenu.
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-InventoryMenu {
    param([hashtable]$Dom)
    Write-Header "INVENTORY & DISCOVERY"
    $choice = Read-Choice "Select:" @(
        "Full domain discovery       (Standard + MSA + gMSA, all OUs)",
        "Standard accounts only",
        "MSA accounts only",
        "gMSA accounts only",
        "Health audit on all accounts",
        "Export to HTML report",
        "Export to CSV",
        "← Back"
    )
    switch ($choice) {
        0 {
            $inv = Get-AllServiceAccounts $Dom
            if ($inv) { Show-Paged $inv @("Type","SamAccountName","Enabled","PasswordDaysLeft","LastLogon","SecurityFlags","NamingOK") }
        }
        1 {
            $inv = Get-AllServiceAccounts $Dom
            if ($inv) { Show-Paged ($inv | Where-Object Type -eq "Standard") @("SamAccountName","Enabled","LockedOut","PasswordDaysLeft","LastLogon","SecurityFlags") }
        }
        2 {
            $inv = Get-AllServiceAccounts $Dom
            if ($inv) { Show-Paged ($inv | Where-Object Type -eq "MSA") @("SamAccountName","Enabled","OU") }
        }
        3 {
            $inv = Get-AllServiceAccounts $Dom
            if ($inv) { Show-Paged ($inv | Where-Object Type -eq "gMSA") @("SamAccountName","Enabled","PasswordDaysLeft","OU") }
        }
        4 { $inv = Get-AllServiceAccounts $Dom; if ($inv) { Show-HealthAudit $inv } }
        5 { $inv = Get-AllServiceAccounts $Dom; if ($inv) { Export-InventoryHTML $inv $Dom } }
        6 {
            $inv = Get-AllServiceAccounts $Dom
            if ($inv) {
                $csvPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "SvcAcct_Inventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                $inv | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
                Write-OK "Exported $($inv.Count) account(s) to: $csvPath"
                Write-AuditLog "INVENTORY_CSV" "DOMAIN" "SUCCESS" "File=$csvPath Count=$($inv.Count)"
            }
        }
        7 { return }
    }
    Pause-Screen
}

<#
.SYNOPSIS
    Discovers ALL service accounts in a domain using server-side LDAP filters.
.DESCRIPTION
    Issues targeted, server-filtered LDAP queries rather than loading all user objects
    into memory — essential for large domains with tens of thousands of accounts.

    Discovery strategy (Standard accounts):
      Query 1: PasswordNeverExpires=true AND CannotChangePassword=true
               — characteristic of deliberately configured service accounts.
      Query 2: ServicePrincipalName has any value
               — accounts registered for Kerberos service ticket issuance.
      Query 3: SamAccountName starts with a known service-account prefix
               — catches accounts that match naming conventions.
      All three result sets are merged and deduplicated.

    MSA and gMSA accounts are discovered via Get-ADServiceAccount filtered by ObjectClass.

    Each returned record includes pre-computed security flags so callers do not need
    to make additional AD queries for the most common security checks.
.PARAMETER Dom  Domain info hashtable (FQDN, DN, NetBIOS, PDC).
.OUTPUTS   [System.Collections.Generic.List[PSCustomObject]]  Enriched account records.
#>
function Get-AllServiceAccounts {
    param([hashtable]$Dom)
    Write-Step "Discovering service accounts in $($Dom.FQDN) (server-side filtered LDAP)..."

    $results  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $domPolicy = Get-ADDefaultDomainPasswordPolicy

    # Common properties to retrieve for Standard user accounts
    $stdProps = @(
        "DisplayName","Description","Department","ManagedBy","Enabled","PasswordNeverExpires",
        "PasswordLastSet","PasswordExpired","LockedOut","LastLogonDate","AccountExpirationDate",
        "BadLogonCount","ServicePrincipalName","MemberOf","CannotChangePassword","adminCount",
        "TrustedForDelegation","DoesNotRequirePreAuth","AllowReversiblePasswordEncryption",
        "PasswordNotRequired","DistinguishedName","Created","Modified","LogonWorkstations","SIDHistory"
    )
    $queryParams = @{ SearchBase = $Dom.DN; Properties = $stdProps; Server = $Dom.PDC }

    # ── Standard user accounts ─────────────────────────────────────────────
    try {
        # Query 1: Password policy indicators
        $q1 = Get-ADUser -Filter {
            PasswordNeverExpires -eq $true -and CannotChangePassword -eq $true
        } @queryParams -EA SilentlyContinue

        # Query 2: Accounts with registered SPNs (Kerberoastable candidates)
        $q2 = Get-ADUser -Filter {
            ServicePrincipalName -like "*"
        } @queryParams -EA SilentlyContinue

        # Query 3: Naming-convention matches — one server-side query per prefix
        $q3 = @()
        foreach ($prefix in @("svc_","svc-","sa_","sa-","msa_","gmsa_","adm_svc","_svc")) {
            $p    = $prefix  # Capture for use inside filter script block
            $q3  += Get-ADUser -Filter { SamAccountName -like "$p*" } @queryParams -EA SilentlyContinue
        }

        # Merge and deduplicate all three query result sets
        $combined = @($q1) + @($q2) + @($q3) |
                    Sort-Object SamAccountName -Unique |
                    Where-Object { $_ }

        foreach ($u in $combined) {
            # Calculate password days remaining using PSO or domain policy
            $daysLeft = if ($u.PasswordNeverExpires -or
                            -not $u.PasswordLastSet -or
                            $domPolicy.MaxPasswordAge.TotalDays -eq 0) {
                "∞"
            }
            else {
                [int](($u.PasswordLastSet + $domPolicy.MaxPasswordAge - (Get-Date)).TotalDays)
            }

            # Pre-compute security flags as a pipe-delimited string for easy display and filtering
            $secFlags = @()
            if ($u.TrustedForDelegation)              { $secFlags += "UNCONSTRAINED_DELEG" }
            if ($u.DoesNotRequirePreAuth)              { $secFlags += "ASREP_ROASTABLE" }
            if ($u.AllowReversiblePasswordEncryption)  { $secFlags += "REVERSIBLE_ENC" }
            if ($u.PasswordNotRequired)                { $secFlags += "PASSWD_NOTREQD" }
            if ($u.adminCount -eq 1)                   { $secFlags += "SHADOW_ADMIN" }
            if (@($u.SIDHistory).Count -gt 0)          { $secFlags += "SID_HISTORY" }
            if (@($u.ServicePrincipalName).Where({ $_ }).Count -gt 0) { $secFlags += "KERBEROASTABLE" }

            $results.Add([PSCustomObject]@{
                Type                 = "Standard"
                SamAccountName       = $u.SamAccountName
                DisplayName          = $u.DisplayName
                Description          = $u.Description
                Department           = $u.Department
                Enabled              = $u.Enabled
                LockedOut            = $u.LockedOut
                PasswordExpired      = $u.PasswordExpired
                PasswordNeverExpires = $u.PasswordNeverExpires
                PasswordLastSet      = $u.PasswordLastSet
                PasswordDaysLeft     = $daysLeft
                LastLogon            = Get-Coalesce $u.LastLogonDate "Never"
                AccountExpires       = Get-Coalesce $u.AccountExpirationDate "Never"
                BadLogonCount        = $u.BadLogonCount
                SPNCount             = @($u.ServicePrincipalName).Where({ $_ }).Count
                GroupCount           = @($u.MemberOf).Where({ $_ }).Count
                SecurityFlags        = $secFlags -join "|"
                NamingOK             = Test-NamingConvention $u.SamAccountName
                LogonRestricted      = [bool]$u.LogonWorkstations
                ManagedBy            = $u.ManagedBy -replace '^CN=([^,]+).*', '$1'
                OU                   = $u.DistinguishedName -replace '^CN=[^,]+,', ''
                Created              = $u.Created
                LastModified         = $u.Modified
            })
        }
        Write-OK "Standard: $($results.Where({ $_.Type -eq 'Standard' }).Count) account(s) found."
    }
    catch { Write-Fail "Standard account discovery error: $($_.Exception.Message)" }

    # ── MSA accounts ──────────────────────────────────────────────────────
    try {
        $msas = Get-ADServiceAccount -SearchBase $Dom.DN `
                    -Filter { ObjectClass -eq "msDS-ManagedServiceAccount" } `
                    -Properties Description, Enabled, Created, Modified, DistinguishedName,
                               KerberosEncryptionType, HostComputers `
                    -Server $Dom.PDC

        foreach ($sa in $msas) {
            $results.Add([PSCustomObject]@{
                Type                 = "MSA"
                SamAccountName       = $sa.SamAccountName
                DisplayName          = $sa.SamAccountName
                Description          = $sa.Description
                Department           = "N/A"
                Enabled              = $sa.Enabled
                LockedOut            = "N/A"
                PasswordExpired      = "Auto-managed"
                PasswordNeverExpires = "Auto-managed"
                PasswordLastSet      = "Auto-managed"
                PasswordDaysLeft     = "Auto-managed"
                LastLogon            = "N/A"
                AccountExpires       = "Never"
                BadLogonCount        = "N/A"
                SPNCount             = "N/A"
                GroupCount           = "N/A"
                SecurityFlags        = ""
                NamingOK             = Test-NamingConvention $sa.SamAccountName
                LogonRestricted      = "N/A"
                ManagedBy            = "Auto-managed"
                OU                   = $sa.DistinguishedName -replace '^CN=[^,]+,', ''
                Created              = $sa.Created
                LastModified         = $sa.Modified
            })
        }
        Write-OK "MSA: $($results.Where({ $_.Type -eq 'MSA' }).Count) account(s) found."
    }
    catch { Write-Fail "MSA discovery error: $($_.Exception.Message)" }

    # ── gMSA accounts ─────────────────────────────────────────────────────
    try {
        $gmsas = Get-ADServiceAccount -SearchBase $Dom.DN `
                     -Filter { ObjectClass -eq "msDS-GroupManagedServiceAccount" } `
                     -Properties Description, Enabled, Created, Modified, DistinguishedName,
                                ManagedPasswordIntervalInDays, KerberosEncryptionType,
                                PrincipalsAllowedToRetrieveManagedPassword `
                     -Server $Dom.PDC

        foreach ($sa in $gmsas) {
            $principalCount = @($sa.PrincipalsAllowedToRetrieveManagedPassword).Where({ $_ }).Count
            $results.Add([PSCustomObject]@{
                Type                 = "gMSA"
                SamAccountName       = $sa.SamAccountName
                DisplayName          = $sa.SamAccountName
                Description          = $sa.Description
                Department           = "N/A"
                Enabled              = $sa.Enabled
                LockedOut            = "N/A"
                PasswordExpired      = "Auto-managed"
                PasswordNeverExpires = "Auto-managed"
                PasswordLastSet      = "Auto-managed"
                # Show the rotation interval so the operator knows how often the password changes
                PasswordDaysLeft     = "Auto ($($sa.ManagedPasswordIntervalInDays)d rotation)"
                LastLogon            = "N/A"
                AccountExpires       = "Never"
                BadLogonCount        = "N/A"
                SPNCount             = "N/A"
                GroupCount           = $principalCount   # Reuse GroupCount for principal count
                SecurityFlags        = ""
                NamingOK             = Test-NamingConvention $sa.SamAccountName
                LogonRestricted      = "N/A"
                ManagedBy            = "Auto-managed"
                OU                   = $sa.DistinguishedName -replace '^CN=[^,]+,', ''
                Created              = $sa.Created
                LastModified         = $sa.Modified
            })
        }
        Write-OK "gMSA: $($results.Where({ $_.Type -eq 'gMSA' }).Count) account(s) found."
    }
    catch { Write-Fail "gMSA discovery error: $($_.Exception.Message)" }

    Write-Info "Total discovered: $($results.Count) service account(s)."
    Write-AuditLog "INVENTORY_DISCOVERY" $Dom.FQDN "INFO" "Total=$($results.Count)"
    return $results
}

<#
.SYNOPSIS
    Runs a comprehensive health audit across all discovered accounts and surfaces issues.
.DESCRIPTION
    For each account, checks:
      Enabled, LockedOut, PasswordExpired, PasswordNeverExpires, BadLogonCount,
      AccountExpires, PasswordDaysLeft (warn threshold), Stale logon, NeverLoggedOn,
      Description present, Owner/ManagedBy set, SecurityFlags, NamingOK.
    Results are printed per-account with detailed issue breakdowns.
    A summary is shown at the end; optionally emailed if SMTP is configured.
.PARAMETER Inv  Output from Get-AllServiceAccounts.
#>
function Show-HealthAudit {
    param([System.Collections.Generic.List[PSCustomObject]]$Inv)
    Write-Sub "Health Audit — All Accounts"

    $issues = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($acct in $Inv) {
        $flags = @()

        # Basic account state
        if ($acct.Enabled -eq $false)                                                       { $flags += "DISABLED" }
        if ($acct.LockedOut -eq $true)                                                      { $flags += "LOCKED_OUT" }
        if ($acct.PasswordExpired -eq $true)                                                { $flags += "PWD_EXPIRED" }

        # Password expiry configuration (Standard accounts only)
        if ($acct.Type -eq "Standard" -and $acct.PasswordNeverExpires -eq $false)          { $flags += "PWD_CAN_EXPIRE" }

        # High bad logon count may indicate brute-force or misconfigured application
        if ($acct.BadLogonCount -is [int] -and $acct.BadLogonCount -gt 5)                  { $flags += "HIGH_BAD_LOGONS($($acct.BadLogonCount))" }

        # Expired account expiration date
        if ($acct.AccountExpires -ne "Never" -and $acct.AccountExpires -ne "N/A") {
            try {
                if ([datetime]$acct.AccountExpires -lt (Get-Date))                         { $flags += "ACCT_EXPIRED" }
            }
            catch {}
        }

        # Password expiry approaching within the warning window
        if ($acct.PasswordDaysLeft -is [int] -and $acct.PasswordDaysLeft -lt $CFG.PwdWarnDays) {
            $flags += "PWD_EXPIRING_SOON($($acct.PasswordDaysLeft)d)"
        }

        # Stale: enabled but not used within the configured threshold
        if ($acct.LastLogon -and $acct.LastLogon -ne "N/A" -and $acct.LastLogon -ne "Never") {
            try {
                if ([datetime]$acct.LastLogon -lt (Get-Date).AddDays(-$CFG.StaleThresholdDays)) {
                    $flags += "STALE_>$($CFG.StaleThresholdDays)D"
                }
            }
            catch {}
        }

        # Never logged on
        if (-not $acct.LastLogon -or $acct.LastLogon -eq "Never")                         { $flags += "NEVER_LOGGED_ON" }

        # Governance: missing description or owner
        if (-not $acct.Description)                                                        { $flags += "NO_DESCRIPTION" }
        if (-not $acct.ManagedBy -or $acct.ManagedBy -in @("N/A","Auto-managed",""))      { $flags += "NO_OWNER" }

        # Security flags from inventory (pre-computed in Get-AllServiceAccounts)
        if ($acct.SecurityFlags)                                                           { $flags += "SEC:$($acct.SecurityFlags)" }

        # Naming convention
        if (-not $acct.NamingOK)                                                           { $flags += "NAMING_VIOLATION" }

        # Display result line
        $colour = if ($flags) { "DarkYellow" } else { "Green" }
        Write-Host ("  {0,-32} [{1,-8}] {2}" -f $acct.SamAccountName, $acct.Type, (if ($flags) { "⚠  ISSUES" } else { "✔  OK" })) -ForegroundColor $colour

        if ($flags) {
            $flags | ForEach-Object { Write-Host "       → $_" -ForegroundColor Red }
            $issues.Add([PSCustomObject]@{
                Account = $acct.SamAccountName
                Type    = $acct.Type
                Issues  = $flags -join " | "
            })
        }
    }

    # ── Summary ───────────────────────────────────────────────────────────────
    Write-Sub "Health Audit Summary"
    Write-OK   "Total accounts  : $($Inv.Count)"
    Write-OK   "Healthy         : $($Inv.Count - $issues.Count)"

    if ($issues.Count -gt 0) {
        Write-Fail "With issues     : $($issues.Count)"
        Write-AuditLog "HEALTH_AUDIT" "DOMAIN" "FAILURE" "Issues=$($issues.Count) Total=$($Inv.Count)"

        if ($SmtpAlert -or (Confirm-Action "Send health audit report by email?")) {
            $body  = "<h2>Service Account Health Audit — $($issues.Count) issue(s)</h2>"
            $body += "<table border='1' style='border-collapse:collapse'>"
            $body += "<tr><th>Account</th><th>Type</th><th>Issues</th></tr>"
            $issues | ForEach-Object {
                $body += "<tr><td>$($_.Account)</td><td>$($_.Type)</td><td>$($_.Issues)</td></tr>"
            }
            $body += "</table>"
            Send-AlertEmail "AD Service Account Health Audit — $(Get-Date -Format 'yyyy-MM-dd')" $body
        }
    }
    else {
        Write-OK "All accounts healthy."
        Write-AuditLog "HEALTH_AUDIT" "DOMAIN" "SUCCESS" "AllHealthy Total=$($Inv.Count)"
    }
}

<#
.SYNOPSIS  Generates a searchable, self-contained HTML inventory report.
.DESCRIPTION
    Produces a dark-themed HTML file with:
      - Summary stat cards (totals by type, disabled, locked, security flags, naming violations)
      - A live client-side filter input
      - A full sortable table of all discovered accounts
    The report is saved to the reports directory and optionally opened in the default browser.
.PARAMETER Inv  Output from Get-AllServiceAccounts.
.PARAMETER Dom  Domain info hashtable.
#>
function Export-InventoryHTML {
    param([System.Collections.Generic.List[PSCustomObject]]$Inv, [hashtable]$Dom)
    Write-Step "Generating HTML inventory report..."

    # Pre-compute summary statistics
    $total = $Inv.Count
    $std   = ($Inv | Where-Object Type -eq "Standard").Count
    $msa   = ($Inv | Where-Object Type -eq "MSA").Count
    $gmsa  = ($Inv | Where-Object Type -eq "gMSA").Count
    $dis   = ($Inv | Where-Object { $_.Enabled -eq $false }).Count
    $lk    = ($Inv | Where-Object { $_.LockedOut -eq $true }).Count
    $sec   = ($Inv | Where-Object { $_.SecurityFlags }).Count
    $nm    = ($Inv | Where-Object { -not $_.NamingOK }).Count

    # Build table rows — colour coded by type and security status
    $rows = $Inv | ForEach-Object {
        $typeColour  = switch ($_.Type) { "Standard" { "#3b82f6" } "MSA" { "#a855f7" } "gMSA" { "#22c55e" } }
        $enColour    = if ($_.Enabled -eq $true) { "#22c55e" } elseif ($_.Enabled -eq $false) { "#ef4444" } else { "#888" }
        $secColour   = if ($_.SecurityFlags) { "#ef4444" } else { "#6b7280" }
        $namingIcon  = if ($_.NamingOK) { '<span style="color:#22c55e">✔</span>' } else { '<span style="color:#ef4444">⚠</span>' }
        $secDisplay  = if ($_.SecurityFlags) { $_.SecurityFlags } else { "—" }
        $createdStr  = if ($_.Created) { try { ([datetime]$_.Created).ToString('yyyy-MM-dd') } catch { "" } } else { "" }
        $ouShort     = $_.OU -replace 'OU=([^,]+),.*', '$1...'

        "<tr>
          <td><span style='background:$typeColour;padding:2px 8px;border-radius:4px;font-size:.8em;color:#fff'>$($_.Type)</span></td>
          <td><b>$($_.SamAccountName)</b></td>
          <td style='color:$enColour'>$($_.Enabled)</td>
          <td>$($_.PasswordDaysLeft)</td>
          <td>$($_.LastLogon)</td>
          <td style='color:$secColour;font-size:.75em'>$secDisplay</td>
          <td>$namingIcon</td>
          <td style='font-size:.8em;color:#9ca3af'>$($_.Description)</td>
          <td style='font-size:.75em;color:#6b7280'>$ouShort</td>
          <td>$createdStr</td>
        </tr>"
    }

    $reportPath = Join-Path $REPORT_DIR "Inventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Service Account Inventory — $($Dom.FQDN)</title>
  <style>
    body  { font-family: Segoe UI, sans-serif; background: #111827; color: #e5e7eb; margin: 0; padding: 24px; }
    h1    { color: #60a5fa; border-bottom: 2px solid #1e40af; padding-bottom: 10px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(110px,1fr)); gap: 12px; margin: 18px 0; }
    .card { background: #1f2937; border-radius: 10px; padding: 14px; text-align: center; border: 1px solid #374151; }
    .card .n { font-size: 2em; font-weight: 700; }
    .card .l { font-size: .75em; color: #9ca3af; margin-top: 3px; }
    .blue { color: #60a5fa; } .purple { color: #a855f7; } .green { color: #22c55e; }
    .red  { color: #ef4444; } .yellow { color: #f59e0b; } .white { color: #f9fafb; }
    table { width: 100%; border-collapse: collapse; font-size: .86em; margin-top: 12px; }
    th { background: #1e3a5f; color: #93c5fd; padding: 9px; text-align: left; font-size: .78em;
         text-transform: uppercase; letter-spacing: .06em; position: sticky; top: 0; }
    td { padding: 7px 10px; border-bottom: 1px solid #1f2937; vertical-align: middle; }
    tr:hover { background: #1e2f4a; }
    input { background: #1f2937; border: 1px solid #374151; color: #e5e7eb; padding: 6px 14px;
            border-radius: 6px; width: 280px; margin-bottom: 10px; }
    .footer { margin-top: 20px; color: #374151; font-size: .78em; }
  </style>
</head>
<body>
<h1>🗂 Service Account Inventory</h1>
<p style="color:#6b7280">
  Domain: <b>$($Dom.FQDN)</b> &nbsp;·&nbsp;
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;·&nbsp;
  Operator: $env:USERDOMAIN\$env:USERNAME
</p>
<div class="grid">
  <div class="card"><div class="n white">$total</div><div class="l">Total</div></div>
  <div class="card"><div class="n blue">$std</div><div class="l">Standard</div></div>
  <div class="card"><div class="n purple">$msa</div><div class="l">MSA</div></div>
  <div class="card"><div class="n green">$gmsa</div><div class="l">gMSA</div></div>
  <div class="card"><div class="n red">$dis</div><div class="l">Disabled</div></div>
  <div class="card"><div class="n yellow">$lk</div><div class="l">Locked</div></div>
  <div class="card"><div class="n red">$sec</div><div class="l">Sec Flags</div></div>
  <div class="card"><div class="n yellow">$nm</div><div class="l">Naming ⚠</div></div>
</div>
<input id="f" onkeyup="ft()" placeholder="🔍 Filter accounts...">
<table id="t">
  <thead><tr>
    <th>Type</th><th>SAM Name</th><th>Enabled</th><th>Pwd Days</th>
    <th>Last Logon</th><th>Security Flags</th><th>Naming</th>
    <th>Description</th><th>OU</th><th>Created</th>
  </tr></thead>
  <tbody>$($rows -join "`n")</tbody>
</table>
<script>
  function ft() {
    var f = document.getElementById('f').value.toLowerCase();
    var rows = document.getElementById('t').rows;
    for (var i = 1; i < rows.length; i++) {
      rows[i].style.display = rows[i].innerText.toLowerCase().includes(f) ? '' : 'none';
    }
  }
</script>
<div class="footer">AD Service Account Manager v$SCRIPT_VERSION &nbsp;·&nbsp; Log: $AUDIT_LOG</div>
</body>
</html>
"@
    $html | Set-Content $reportPath -Encoding UTF8
    Write-OK "HTML report saved: $reportPath"
    Write-AuditLog "INVENTORY_HTML" "DOMAIN" "SUCCESS" "File=$reportPath Count=$total"
    if (Confirm-Action "Open report in browser?") { Start-Process $reportPath }
}

# ══════════════════════════════════════════════════════════════════════════════
#  AUDIT MODULE — Log review, integrity, SIEM export, baseline, drift detection
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS  Entry point for the Audit submenu.
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-AuditMenu {
    param([hashtable]$Dom)
    Write-Header "AUDIT & REPORTING"
    $choice = Read-Choice "Select:" @(
        "View audit log              (last 50 entries)",
        "Search / filter audit log",
        "Verify log integrity        (SHA-256 hash check)",
        "Generate HTML audit report",
        "Read AD security event log  (logon/lockout events)",
        "Export → JSON  (SIEM ingestion)",
        "Export → CEF   (Splunk / QRadar)",
        "Export → Syslog",
        "Save account baseline snapshot",
        "Run drift detection vs saved baseline",
        "View change history for a specific account",
        "Export raw audit log CSV",
        "Register as Windows Scheduled Task",
        "Clear audit log",
        "← Back"
    )
    switch ($choice) {
        0 {
            if (Test-Path $AUDIT_LOG) {
                Show-Paged (Import-Csv $AUDIT_LOG | Select-Object -Last 50) `
                    @("Timestamp","Operator","Action","Target","Result","Details")
            }
            else { Write-Info "No audit log found yet." }
        }
        1 {
            if (-not (Test-Path $AUDIT_LOG)) { Write-Info "No audit log found."; break }
            $query = Read-Host "  Search term (ENTER = show all)"
            $data  = Import-Csv $AUDIT_LOG
            if ($query) {
                $data = $data | Where-Object {
                    $_.Target  -like "*$query*" -or $_.Action  -like "*$query*" -or
                    $_.Result  -like "*$query*" -or $_.Operator -like "*$query*"
                }
            }
            if ($data) {
                Show-Paged $data @("Timestamp","Operator","Action","Target","Result","Details")
                Write-Info "Matches: $($data.Count)"
            }
            else { Write-Info "No matching entries found." }
        }
        2  { Test-AuditLogIntegrity }
        3  { Export-HTMLAuditReport }
        4  { Read-ADSecurityLog (Read-SAMName "SAM Account Name") }
        5  { Export-SIEMJson   (Join-Path ([Environment]::GetFolderPath("Desktop")) "audit_siem_$(Get-Date -Format 'yyyyMMdd').json") }
        6  { Export-SIEMCef    (Join-Path ([Environment]::GetFolderPath("Desktop")) "audit_siem_$(Get-Date -Format 'yyyyMMdd').cef") }
        7  { Export-SIEMSyslog (Join-Path ([Environment]::GetFolderPath("Desktop")) "audit_siem_$(Get-Date -Format 'yyyyMMdd').log") }
        8  { Save-Baseline $Dom }
        9  { Compare-Baseline $Dom }
        10 {
            $target = Read-SAMName "SAM Account Name"
            if (Test-Path $AUDIT_LOG) {
                $history = Import-Csv $AUDIT_LOG | Where-Object { $_.Target -eq $target } | Sort-Object Timestamp
                if ($history) { Show-Paged $history @("Timestamp","Operator","Action","Result","Details") }
                else          { Write-Info "No audit history found for '$target'." }
            }
            else { Write-Info "No audit log found." }
        }
        11 {
            if (Test-Path $AUDIT_LOG) {
                $csvPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                Copy-Item $AUDIT_LOG $csvPath -Force
                Write-OK "Audit log exported to: $csvPath"
            }
            else { Write-Info "No audit log found." }
        }
        12 { Invoke-RegisterScheduledTask }
        13 {
            if (Confirm-Action "CLEAR the entire audit log? This cannot be undone.") {
                Remove-Item $AUDIT_LOG, $AUDIT_HASH -Force -EA SilentlyContinue
                Write-Warn "Audit log cleared."
                Write-AuditLog "AUDIT_LOG_CLEARED" "SYSTEM" "INFO" "By=$env:USERNAME"
            }
        }
        14 { return }
    }
    Pause-Screen
}

<#
.SYNOPSIS  Generates a searchable, dark-themed HTML audit report with compliance cross-references.
.DESCRIPTION
    Produces a self-contained HTML report from the current audit log, including:
      - Summary stat cards (total, success, failure, info, WhatIf)
      - A live client-side filter input
      - Per-row compliance framework references (CIS, NIST, ISO 27001) for key actions
    Saved to the reports directory and optionally opened in the browser.
#>
function Export-HTMLAuditReport {
    if (-not (Test-Path $AUDIT_LOG)) { Write-Info "No audit log found."; return }

    $rows     = Import-Csv $AUDIT_LOG
    $total    = $rows.Count
    $succCount = ($rows | Where-Object Result -eq "SUCCESS").Count
    $failCount = ($rows | Where-Object Result -eq "FAILURE").Count
    $infoCount = ($rows | Where-Object Result -eq "INFO").Count
    $whatCount = ($rows | Where-Object Result -eq "WHATIF").Count

    # Compliance cross-references for the most common audit actions
    $complianceMap = @{
        "CREATE"           = "CIS L1 | NIST AC-2 | ISO A.9.2.1"
        "DELETE"           = "CIS L1 | NIST AC-2 | ISO A.9.2.6"
        "PASSWORD_RESET"   = "CIS L1 | NIST IA-5 | ISO A.9.4.3"
        "SEC_KERBEROAST"   = "CIS L2 | NIST SI-3 | ISO A.12.6"
        "SEC_SHADOW_ADMIN" = "CIS L2 | NIST AC-6 | ISO A.9.2.3"
        "GROUP_ADD"        = "NIST AC-2 | ISO A.9.2.2"
        "TOGGLE_ENABLE"    = "NIST AC-2 | ISO A.9.2.6"
        "CLONE"            = "NIST AC-2 | ISO A.9.2.1"
        "MOVE_OU"          = "NIST AC-2 | ISO A.9.2.5"
        "RENAME"           = "NIST AC-2 | ISO A.9.2.5"
        "SET_EXPIRY"       = "CIS L1 | NIST AC-2(3)"
        "SEC_ASREP"        = "CIS L2 | NIST IA-5 | ISO A.9.4.2"
        "BULK_CREATE"      = "NIST AC-2 | ISO A.9.2.1"
    }

    $tableRows = $rows | ForEach-Object {
        $resultColour = switch ($_.Result) {
            "SUCCESS" { "#166534" } "FAILURE" { "#991b1b" } "WHATIF" { "#5b21b6" } default { "#374151" }
        }
        $complianceRef = if ($complianceMap.ContainsKey($_.Action)) { $complianceMap[$_.Action] } else { "" }
        "<tr>
          <td>$($_.Timestamp)</td>
          <td>$($_.Operator)</td>
          <td><b>$($_.Action)</b></td>
          <td>$($_.Target)</td>
          <td style='color:$resultColour;font-weight:bold'>$($_.Result)</td>
          <td style='font-size:.8em;color:#9ca3af'>$($_.Details)</td>
          <td style='font-size:.75em;color:#6b7280'>$complianceRef</td>
        </tr>"
    }

    $reportPath = Join-Path $REPORT_DIR "AuditReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Audit Report — AD Service Account Manager</title>
  <style>
    body  { font-family: Segoe UI, sans-serif; background: #0f172a; color: #e2e8f0; padding: 22px; }
    h1    { color: #38bdf8; border-bottom: 2px solid #0369a1; padding-bottom: 10px; }
    .stats { display: flex; gap: 14px; margin: 16px 0; flex-wrap: wrap; }
    .stat { background: #1e293b; border-radius: 8px; padding: 13px 20px; text-align: center; min-width: 90px; }
    .stat .n { font-size: 1.9em; font-weight: 700; }
    .stat .l { font-size: .76em; color: #94a3b8; }
    .t  { color: #38bdf8; } .s { color: #22c55e; } .f { color: #ef4444; }
    .i  { color: #f59e0b; } .w { color: #a78bfa; }
    table { width: 100%; border-collapse: collapse; font-size: .87em; }
    th { background: #0c4a6e; color: #7dd3fc; padding: 9px; text-align: left; font-size: .77em;
         text-transform: uppercase; position: sticky; top: 0; }
    td { padding: 7px 9px; border-bottom: 1px solid #1e293b; vertical-align: top; }
    tr:hover { background: #1e293b; }
    input { background: #1e293b; border: 1px solid #334155; color: #e2e8f0; padding: 6px 13px;
            border-radius: 6px; width: 260px; margin-bottom: 10px; }
    .footer { margin-top: 16px; color: #334155; font-size: .76em; text-align: center; }
  </style>
</head>
<body>
<h1>🛡 Audit Report</h1>
<p style="color:#64748b">$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;·&nbsp; $env:USERDOMAIN\$env:USERNAME</p>
<div class="stats">
  <div class="stat"><div class="n t">$total</div><div class="l">Total</div></div>
  <div class="stat"><div class="n s">$succCount</div><div class="l">Success</div></div>
  <div class="stat"><div class="n f">$failCount</div><div class="l">Failures</div></div>
  <div class="stat"><div class="n i">$infoCount</div><div class="l">Info</div></div>
  <div class="stat"><div class="n w">$whatCount</div><div class="l">WhatIf</div></div>
</div>
<input id="f" onkeyup="ft()" placeholder="🔍 Filter...">
<table id="t">
  <thead><tr>
    <th>Timestamp</th><th>Operator</th><th>Action</th><th>Target</th>
    <th>Result</th><th>Details</th><th>Compliance Refs</th>
  </tr></thead>
  <tbody>$($tableRows -join "`n")</tbody>
</table>
<script>
  function ft() {
    var f = document.getElementById('f').value.toLowerCase();
    var r = document.getElementById('t').rows;
    for (var i = 1; i < r.length; i++) {
      r[i].style.display = r[i].innerText.toLowerCase().includes(f) ? '' : 'none';
    }
  }
</script>
<div class="footer">AD Service Account Manager v$SCRIPT_VERSION &nbsp;·&nbsp; $AUDIT_LOG</div>
</body>
</html>
"@
    $html | Set-Content $reportPath -Encoding UTF8
    Write-OK "HTML audit report saved: $reportPath"
    Write-AuditLog "EXPORT_AUDIT_HTML" "SYSTEM" "SUCCESS" "File=$reportPath"
    if (Confirm-Action "Open report in browser?") { Start-Process $reportPath }
}

<#
.SYNOPSIS
    Reads Windows Security event log entries related to a specific account (last 7 days).
.DESCRIPTION
    Queries the local Security log for the most relevant event IDs:
      4624  — Successful logon
      4625  — Failed logon (wrong password)
      4648  — Logon using explicit credentials (RunAs / credential passing)
      4720  — Account created
      4722  — Account enabled
      4723  — Password change attempt (by account)
      4724  — Password reset (by admin)
      4725  — Account disabled
      4726  — Account deleted
      4740  — Account locked out
      4768  — Kerberos TGT requested
      4771  — Kerberos pre-authentication failure
    Requires running on a DC or with access to the DC's event log for best results.
    Run as local Administrator for access to the Security log.
.PARAMETER Sam  SAM Account Name to filter events for.
#>
function Read-ADSecurityLog {
    param([string]$Sam)
    Write-Sub "Security Events for '$Sam' (last 7 days)"
    Write-Info "Tip: Run on a Domain Controller as Administrator for complete results."
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4624, 4625, 4648, 4720, 4722, 4723, 4724, 4725, 4726, 4740, 4768, 4771
            StartTime = (Get-Date).AddDays(-7)
        } -EA SilentlyContinue |
        Where-Object { $_.Message -match [regex]::Escape($Sam) } |
        Select-Object -First 50

        if ($events) {
            $events | Select-Object TimeCreated,
                @{ N="EventID"; E={ $_.Id } },
                @{ N="Level";   E={ $_.LevelDisplayName } },
                @{ N="Summary"; E={ ($_.Message -split "`n" | Select-Object -First 2) -join " | " } } |
                Format-Table -AutoSize -Wrap
            Write-AuditLog "READ_EVENT_LOG" $Sam "SUCCESS" "Found=$($events.Count)"
        }
        else { Write-Info "No matching security events found."; Write-AuditLog "READ_EVENT_LOG" $Sam "INFO" "None" }
    }
    catch { Write-Warn "Event log access failed — run as Administrator on a DC: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
    Saves a baseline snapshot of all current service accounts for later drift comparison.
.DESCRIPTION
    Captures: SamAccountName, Type, Enabled, SecurityFlags, PasswordDaysLeft, OU.
    The snapshot is saved as JSON to the app directory and also archived in the history
    folder with a timestamp suffix for historical diff capability.
    Run Save-Baseline before making any significant changes to the service account
    landscape (batch creations, migrations, restructuring).
.PARAMETER Dom  Domain info hashtable.
#>
function Save-Baseline {
    param([hashtable]$Dom)
    Write-Step "Saving account baseline snapshot for domain $($Dom.FQDN)..."
    $inv = Get-AllServiceAccounts $Dom

    $snapshot = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Operator  = "$env:USERDOMAIN\$env:USERNAME"
        Domain    = $Dom.FQDN
        # Store only the columns needed for drift detection
        Accounts  = $inv | Select-Object SamAccountName, Type, Enabled, SecurityFlags, PasswordDaysLeft, OU
    }

    $snapshot | ConvertTo-Json -Depth 10 | Set-Content $BASELINE_FILE -Encoding UTF8

    Write-OK "Baseline saved: $BASELINE_FILE  ($($inv.Count) account(s))"
    Write-AuditLog "BASELINE_SAVE" $Dom.FQDN "SUCCESS" "Count=$($inv.Count)"

    # Archive a timestamped copy so past baselines can be compared
    $archivePath = Join-Path $HISTORY_DIR "baseline_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    Copy-Item $BASELINE_FILE $archivePath
    Write-Info "Archived to: $archivePath"
}

<#
.SYNOPSIS
    Compares the current account landscape against a previously saved baseline.
.DESCRIPTION
    Detects three categories of drift:
      NEW     — Accounts present now that were not in the baseline (recently created).
      DELETED — Accounts in the baseline that no longer exist (deleted or renamed).
      CHANGED — Accounts present in both but with different Enabled, SecurityFlags, or OU.
    Optionally sends an email alert when drift is found.
    Run this regularly (e.g., weekly via scheduled task) to maintain visibility
    into unauthorised or undocumented service account changes.
.PARAMETER Dom  Domain info hashtable.
#>
function Compare-Baseline {
    param([hashtable]$Dom)

    if (-not (Test-Path $BASELINE_FILE)) {
        Write-Fail "No baseline file found. Run 'Save account baseline snapshot' first."
        return
    }

    $raw      = Get-Content $BASELINE_FILE -Raw | ConvertFrom-Json
    # Re-hydrate: ConvertFrom-Json returns PSCustomObjects with untyped values — cast to string for safe comparison
    $baseline = @($raw.Accounts) | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName   = "$($_.SamAccountName)"
            Type             = "$($_.Type)"
            Enabled          = "$($_.Enabled)"
            SecurityFlags    = "$($_.SecurityFlags)"
            PasswordDaysLeft = "$($_.PasswordDaysLeft)"
            OU               = "$($_.OU)"
        }
    }

    $current = Get-AllServiceAccounts $Dom
    Write-Sub "Drift Report — comparing to baseline from $($raw.Timestamp)"

    $baseNames    = $baseline | ForEach-Object { $_.SamAccountName }
    $currentNames = $current  | ForEach-Object { $_.SamAccountName }

    # ── New accounts ──────────────────────────────────────────────────────────
    $added   = $currentNames | Where-Object { $_ -notin $baseNames }
    Write-Sub "New Accounts (not in baseline)"
    if ($added) {
        $added | ForEach-Object { Write-Warn "  + $_" }
        Write-AuditLog "DRIFT_NEW" $Dom.FQDN "INFO" "Count=$($added.Count)"
    }
    else { Write-OK "None." }

    # ── Deleted accounts ──────────────────────────────────────────────────────
    $removed = $baseNames | Where-Object { $_ -notin $currentNames }
    Write-Sub "Deleted Accounts (in baseline, not found now)"
    if ($removed) {
        $removed | ForEach-Object { Write-Fail "  - $_" }
        Write-AuditLog "DRIFT_DELETED" $Dom.FQDN "INFO" "Count=$($removed.Count)"
    }
    else { Write-OK "None." }

    # ── Changed attributes ────────────────────────────────────────────────────
    Write-Sub "Changed Attributes"
    $changedCount = 0
    foreach ($cur in $current) {
        $prev = $baseline | Where-Object { $_.SamAccountName -eq $cur.SamAccountName } | Select-Object -First 1
        if (-not $prev) { continue }  # New account — already captured above

        $diffs = @()
        if ($prev.Enabled       -ne "$($cur.Enabled)")        { $diffs += "Enabled: $($prev.Enabled) → $($cur.Enabled)" }
        if ($prev.SecurityFlags -ne "$($cur.SecurityFlags)")  { $diffs += "SecurityFlags: [$($prev.SecurityFlags)] → [$($cur.SecurityFlags)]" }
        if ($prev.OU            -ne "$($cur.OU)")             { $diffs += "OU moved: [$($prev.OU)] → [$($cur.OU)]" }

        if ($diffs) {
            Write-Warn "  ~ $($cur.SamAccountName)"
            $diffs | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
            $changedCount++
        }
    }
    if ($changedCount -eq 0) { Write-OK "No attribute changes detected." }
    Write-AuditLog "DRIFT_CHECK" $Dom.FQDN "INFO" "Added=$($added.Count) Removed=$($removed.Count) Changed=$changedCount"

    # ── Optional email alert ──────────────────────────────────────────────────
    $totalDrift = $added.Count + $removed.Count + $changedCount
    if ($totalDrift -gt 0 -and ($SmtpAlert -or (Confirm-Action "Send drift report by email?"))) {
        $body  = "<h2>Service Account Drift Report — vs baseline from $($raw.Timestamp)</h2>"
        $body += "<p><b>New accounts ($($added.Count)):</b> $(if ($added) { $added -join ', ' } else { 'None' })</p>"
        $body += "<p><b>Deleted accounts ($($removed.Count)):</b> $(if ($removed) { $removed -join ', ' } else { 'None' })</p>"
        $body += "<p><b>Attribute changes:</b> $changedCount account(s)</p>"
        Send-AlertEmail "AD Service Account Drift Detected — $(Get-Date -Format 'yyyy-MM-dd')" $body
    }
    elseif ($totalDrift -eq 0) { Write-OK "No drift detected — current state matches baseline exactly." }
}

<#
.SYNOPSIS
    Registers this script as a Windows Scheduled Task for automated non-interactive runs.
.DESCRIPTION
    Creates a task that runs this script with one of the non-interactive modes on a
    daily or weekly schedule. The task runs under the current user context at 02:00.
    Requires local Administrator rights to register the task.
    Configure SMTP first (Settings → Configure SMTP) so the task can send email reports.
.NOTES
    The function is named Invoke-RegisterScheduledTask (not Register-ScheduledTask) to
    avoid a name collision with the built-in Register-ScheduledTask cmdlet.
#>
function Invoke-RegisterScheduledTask {
    Write-Sub "Register as Windows Scheduled Task"
    if (-not (Assert-WriteAllowed)) { return }

    $schedChoice = Read-Choice "Run schedule and mode:" @(
        "Daily   — SecurityScan  (recommended for production)",
        "Daily   — HealthCheck",
        "Weekly  — Inventory     (Monday at 02:00)",
        "Weekly  — DriftCheck    (Monday at 02:00)"
    )

    $modeMap  = @{ 0="SecurityScan"; 1="HealthCheck"; 2="Inventory"; 3="DriftCheck" }
    $trigMap  = @{ 0="Daily";        1="Daily";       2="Weekly";    3="Weekly" }
    $modeName = $modeMap[$schedChoice]
    $taskName = "ADSvcAcctMgr_$modeName"

    try {
        $action   = New-ScheduledTaskAction -Execute "powershell.exe" `
                        -Argument "-NonInteractive -WindowStyle Hidden -File `"$PSCommandPath`" -Mode $modeName -SmtpAlert"
        $trigger  = if ($trigMap[$schedChoice] -eq "Daily") {
                        New-ScheduledTaskTrigger -Daily -At "02:00AM"
                    }
                    else {
                        New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "02:00AM"
                    }
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2)

        Register-ScheduledTask `
            -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -RunLevel Highest -Force | Out-Null

        Write-OK "Scheduled task '$taskName' registered ($($trigMap[$schedChoice]) at 02:00)."
        Write-Info "The task runs under your current user account and requires SMTP to be configured for email reports."
        Write-AuditLog "TASK_REGISTER" $taskName "SUCCESS" "Mode=$modeName"
    }
    catch {
        Write-Fail "Task registration failed: $($_.Exception.Message)"
        Write-Info "Registration requires local Administrator rights."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  SETTINGS MODULE — Persistent configuration management
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS  Entry point for the Settings submenu.
.DESCRIPTION
    All settings are persisted to config.json in the application data directory.
    Changes take effect immediately in the current session.
    Password is stored using Windows DPAPI (ConvertFrom-SecureString) and is
    therefore tied to the current Windows user account and machine.
#>
function Invoke-SettingsMenu {
    Write-Header "SETTINGS & CONFIGURATION"
    $choice = Read-Choice "Select:" @(
        "Configure SMTP / email alerts    (password stored with DPAPI)",
        "Set naming convention patterns",
        "Set stale / password warning thresholds",
        "Set console page size",
        "Set privileged groups to monitor",
        "Set compliance framework         (CIS / NIST / ISO 27001)",
        "Manage trusted forests",
        "SMTP timeout and retry settings",
        "View current configuration",
        "Reset all settings to defaults",
        "← Back"
    )
    switch ($choice) {
        0 {
            # SMTP configuration — password encrypted with DPAPI (current user + machine bound)
            $CFG.SmtpServer  = Read-NonEmpty "SMTP Server hostname"  $CFG.SmtpServer
            $CFG.SmtpPort    = [int](Read-NonEmpty "SMTP Port"        "$($CFG.SmtpPort)")
            $CFG.SmtpFrom    = Read-NonEmpty "From address"           $CFG.SmtpFrom
            $CFG.SmtpTo      = Read-NonEmpty "To address"             $CFG.SmtpTo
            $CFG.SmtpUseSsl  = (Read-Choice "Use SSL/TLS?" @("Yes","No") 0) -eq 0

            $smtpUser = Read-Host "  SMTP Username (ENTER to skip / keep anonymous)"
            if ($smtpUser) {
                $CFG.SmtpUser = $smtpUser
                $smtpPwd = Read-Host "  SMTP Password" -AsSecureString
                # Store encrypted — DPAPI, user + machine bound
                $CFG.SmtpPassEncrypted = ConvertFrom-SecureString $smtpPwd
                Write-OK "Password stored with DPAPI encryption (this user/machine only)."
            }
            Save-Config
        }
        1 {
            Write-Info "Current patterns: $($CFG.NamingPatterns -join '  |  ')"
            Write-Info "Each pattern is a PowerShell regex matched against the SamAccountName."
            $raw = Read-NonEmpty "Patterns (comma-separated regexes)" ($CFG.NamingPatterns -join ",")
            $CFG.NamingPatterns = $raw -split "\s*,\s*" | Where-Object { $_ }
            Save-Config
        }
        2 {
            $CFG.StaleThresholdDays = [int](Read-NonEmpty "Stale logon threshold (days)"  "$($CFG.StaleThresholdDays)")
            $CFG.PwdWarnDays        = [int](Read-NonEmpty "Password expiry warning (days)" "$($CFG.PwdWarnDays)")
            $CFG.PwdMaxAgeDays      = [int](Read-NonEmpty "Max password age alert (days)"  "$($CFG.PwdMaxAgeDays)")
            Save-Config
        }
        3 {
            $CFG.PageSize = [int](Read-NonEmpty "Rows per console page" "$($CFG.PageSize)")
            Save-Config
        }
        4 {
            Write-Info "Current privileged groups: $($CFG.AdminGroups -join ', ')"
            $raw = Read-NonEmpty "Group names (comma-separated)" ($CFG.AdminGroups -join ",")
            $CFG.AdminGroups = $raw -split "\s*,\s*" | Where-Object { $_ }
            Save-Config
        }
        5 {
            $fi = Read-Choice "Compliance framework for audit report references:" @(
                "CIS Benchmarks", "NIST SP 800-53", "ISO/IEC 27001"
            ) 0
            $CFG.ComplianceFramework = @("CIS","NIST","ISO27001")[$fi]
            Save-Config
            Write-OK "Compliance framework set to: $($CFG.ComplianceFramework)"
        }
        6 {
            Write-Info "Current trusted forests: $(if ($CFG.TrustedForests) { $CFG.TrustedForests -join ', ' } else { 'None' })"
            $tf = Read-Host "  Forest FQDN to add (ENTER to skip)"
            if ($tf) {
                if ($CFG.TrustedForests -notcontains $tf) {
                    $CFG.TrustedForests += $tf
                    Save-Config
                    Write-OK "Added: $tf"
                }
                else { Write-Info "'$tf' is already in the trusted forests list." }
            }
        }
        7 {
            $CFG.SmtpTimeoutSec = [int](Read-NonEmpty "SMTP timeout per attempt (seconds)" "$($CFG.SmtpTimeoutSec)")
            $CFG.SmtpRetryCount = [int](Read-NonEmpty "SMTP retry attempts"                 "$($CFG.SmtpRetryCount)")
            Save-Config
        }
        8 {
            # Display the current config as formatted JSON
            $CFG | ConvertTo-Json -Depth 5 |
                ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        }
        9 {
            if (Confirm-Action "Reset ALL settings to factory defaults? This cannot be undone.") {
                Remove-Item $CONFIG_FILE -Force -EA SilentlyContinue
                Write-OK "Settings reset. Restart the script to apply defaults."
            }
        }
        10 { return }
    }
    Pause-Screen
}

# ══════════════════════════════════════════════════════════════════════════════
#  NON-INTERACTIVE / SCHEDULED MODE — Headless execution for Task Scheduler
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS
    Executes one of the non-interactive (scheduled / headless) operating modes.
.DESCRIPTION
    Called when -Mode is anything other than "Interactive". No console menus are
    displayed — the mode runs its full scan, writes to the audit log, saves reports,
    and optionally sends an SMTP alert.
    All output is still written to the console so it appears in scheduled task logs
    if stdout/stderr is captured.
    Modes:
      Audit        — Export HTML audit report + SIEM JSON.
      SecurityScan — Run all major security checks.
      Inventory    — Full account discovery, HTML + CSV export.
      DriftCheck   — Compare current state to saved baseline.
      HealthCheck  — Run health audit against all accounts.
.PARAMETER Dom  Domain info hashtable.
#>
function Invoke-ScheduledMode {
    param([hashtable]$Dom)
    Write-Info "Non-interactive mode: $Mode"
    $out = if ($OutputPath) { $OutputPath } else { $REPORT_DIR }

    switch ($Mode) {
        "Audit" {
            Export-HTMLAuditReport
            Export-SIEMJson (Join-Path $out "audit_$(Get-Date -Format 'yyyyMMdd').json")
            if ($SmtpAlert) {
                Send-AlertEmail "AD Audit Report — $(Get-Date -Format 'yyyy-MM-dd')" `
                    "<p>Audit report generated. See attachment or review the report directory.</p>"
            }
        }
        "SecurityScan" {
            Test-Kerberoastable       $Dom
            Test-ASREPRoastable       $Dom
            Test-DelegationSweep      $Dom
            Test-PASSWDNotReqd        $Dom
            Test-ReversibleEncryption $Dom
            Test-ShadowAdmins         $Dom
            Test-SIDHistory           $Dom
            Test-WeakKerberosEncryption $Dom
            if ($SmtpAlert) {
                Send-AlertEmail "AD Security Scan — $($Dom.FQDN) — $(Get-Date -Format 'yyyy-MM-dd')" `
                    "<p>Scheduled security scan completed. Review the audit log for all findings.</p>"
            }
        }
        "Inventory" {
            $inv = Get-AllServiceAccounts $Dom
            if ($inv) {
                Export-InventoryHTML $inv $Dom
                $inv | Export-Csv (Join-Path $out "inventory_$(Get-Date -Format 'yyyyMMdd').csv") `
                    -NoTypeInformation -Encoding UTF8
            }
        }
        "DriftCheck" {
            Compare-Baseline $Dom
        }
        "HealthCheck" {
            $inv = Get-AllServiceAccounts $Dom
            if ($inv) { Show-HealthAudit $inv }
        }
    }
    Write-AuditLog "SCHEDULED_$Mode" "SYSTEM" "SUCCESS" "Output=$out"
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT — Banner, pre-flight checks, and interactive main loop
# ══════════════════════════════════════════════════════════════════════════════

<#
.SYNOPSIS  Prints the application banner with domain, operator, role, and mode flags.
.NOTES     $dom must be resolved before calling this function.
#>
function Show-Banner {
    Clear-Host
    $modeFlags = @()
    if ($script:READONLY) { $modeFlags += "⚠ READ-ONLY" }
    if ($script:WHATIF)   { $modeFlags += "🔵 DRY-RUN" }
    $flagDisplay = if ($modeFlags) { " · " + ($modeFlags -join " · ") } else { "" }

    Write-Host @"
  ╔══════════════════════════════════════════════════════════════════════════╗
  ║   AD SERVICE ACCOUNT MANAGER  v$SCRIPT_VERSION                           ║
  ║   Create · Manage · Test · Security · Virtual · Azure AD · Audit         ║
  ╚══════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    Write-Host ("  Domain  : {0}"            -f $dom.FQDN)                                    -ForegroundColor Gray
    Write-Host ("  PDC     : {0}"            -f $dom.PDC)                                     -ForegroundColor Gray
    Write-Host ("  Operator: {0}\{1}{2}"     -f $env:USERDOMAIN, $env:USERNAME, $flagDisplay) -ForegroundColor Gray
    Write-Host ("  Role    : {0}"            -f $script:ROLE)                                 -ForegroundColor Gray
    Write-Host ("  Log     : {0}"            -f $AUDIT_LOG)                                   -ForegroundColor Gray
    Write-Host ""
}

# ── Pre-flight: connect to AD and verify domain access ────────────────────────
try {
    $dom = Get-DomainInfo -TargetDomain $Domain
}
catch {
    Write-Host "`n  [ERROR] Cannot connect to Active Directory: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Ensure the ActiveDirectory module is installed (RSAT) and you have domain connectivity.`n" -ForegroundColor Red
    exit 1
}

# ── Non-interactive modes: skip role setup and menus entirely ─────────────────
if ($Mode -ne "Interactive") {
    $script:ROLE     = "Scheduled"
    $script:READONLY = $false   # Scheduled modes may need write access (e.g., drift alert)
    Write-AuditLog "SESSION_START" "SYSTEM" "INFO" "Mode=$Mode v=$SCRIPT_VERSION"
    Invoke-ScheduledMode $dom
    Write-AuditLog "SESSION_END" "SYSTEM" "INFO" "Mode=$Mode"
    exit 0
}

# ── Interactive mode: resolve role then enter the main menu loop ──────────────
Invoke-RoleSetup

:mainLoop while ($true) {
    Show-Banner
    $menuChoice = Read-Choice "Main Menu:" @(
        "🆕  CREATE           — Wizard · Clone · Bulk CSV · WhatIf preview",
        "⚙️  MANAGE           — Modify · Reset · Expiry · Recycle Bin · Replication",
        "🔍  TEST             — Health · SPN · Stale · PSO · Protected Users",
        "🔴  SECURITY         — Kerberoast · AS-REP · ACL · SID History · AdminSDHolder",
        "🔗  DEPENDENCY       — Services · Scheduled Tasks · IIS App Pools",
        "👻  VIRTUAL ACCOUNTS — NT SERVICE\* · SYSTEM · LocalService (host scan)",
        "☁️  AZURE AD / ENTRA — Service Principals · Credential Expiry · Permissions",
        "🖥️  COMPUTER ACCTS   — Computer accounts acting as service identities",
        "📋  GROUP POLICY     — GPO impact · Logon rights · Service assignments",
        "🌐  MULTI-FOREST     — Cross-domain / cross-forest inventory & security",
        "🗂  INVENTORY        — Discover all accounts · Health audit · HTML/CSV export",
        "📊  AUDIT            — Logs · SIEM · Baseline · Drift · Scheduled task",
        "⚙️  SETTINGS         — SMTP · Naming · Thresholds · Trusted forests",
        "🚪  EXIT"
    ) 0 Cyan

    switch ($menuChoice) {
        0  { Invoke-CreateMenu                 $dom }
        1  { Invoke-ManageMenu                 $dom }
        2  { Invoke-TestMenu                   $dom }
        3  { Invoke-SecurityMenu               $dom }
        4  { Invoke-DependencyMenu             $dom }
        5  { Invoke-VirtualAccountMenu              }
        6  { Invoke-AzureADMenu                     }
        7  { Invoke-ComputerAccountServiceMenu $dom }
        8  { Invoke-GroupPolicyMenu            $dom }
        9  { Invoke-MultiForestMenu                 }
        10 { Invoke-InventoryMenu              $dom }
        11 { Invoke-AuditMenu                  $dom }
        12 { Invoke-SettingsMenu                    }
        13 {
            Write-AuditLog "SESSION_END" "SYSTEM" "INFO" "Role=$($script:ROLE)"
            Write-Host "`n  Session ended. All actions have been logged to:`n  $AUDIT_LOG`n" -ForegroundColor Cyan
            break mainLoop
        }
    }
}