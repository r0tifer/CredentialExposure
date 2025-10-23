# Get-Pwnd-PassCheck

Get-Pwnd-PassCheck extends the original [PwnedPassCheck](https://github.com/rmbolger/PwnedPassCheck) module with automation capabilities tailored for small and midsize environments. It continues to wrap the [Have I Been Pwned](https://haveibeenpwned.com) Pwned Passwords API, but now layers in Active Directory auditing, automated notifications, managerial reporting, and persistent audit tracking so you can respond to compromised credentials faster.

## Key features

* **Active Directory password auditing** – `Get-PwnedADUserPassword` replicates user password hashes from the domain controllers you define and checks each hash against the Have I Been Pwned API using k-anonymity for privacy.
* **Centralised configuration** – All runtime options (domain controllers, notification preferences, API credentials, etc.) live in `PwnedPassCheckSettings.psd1`, keeping scripted runs and scheduled automation consistent.
* **User notifications** – When enabled, affected users receive a templated email explaining the exposure, the last notification date, and how to reset their password. Emails are throttled to one per account per day.
* **Managerial reporting** – HTML reports summarise exposure counts, notification history, and remediation status. Reports are sent on the cadence you define (weekly or monthly) and tracked so stakeholders are not spammed.
* **Audit log** – Every password audit is written to `C:\PwndPassCheck\PwnedPassCheckAuditLog.json` by default so you can review historical exposure counts, notification state, and password change status with `Get-PwnedAuditLog` and `Update-PwnedAuditLog`.
* **Classic password/hash lookups** – Original commands such as `Get-PwnedPassword`, `Get-PwnedHash`, and their `Test-*` counterparts remain for ad-hoc checks against SHA1 or NTLM datasets and custom API endpoints.

## Requirements

* PowerShell 5.1 or later, or PowerShell 7+
* [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) module installed on the system performing Active Directory audits
* Network access to the Have I Been Pwned API (or a compatible third-party/local mirror)

## Installation

### Latest release

Install the stable version from the PowerShell Gallery or from the latest GitHub release.

```powershell
# Install for all users (requires elevated privileges)
Install-Module -Name PwnedPassCheck -Scope AllUsers

# Install for the current user only
Install-Module -Name PwnedPassCheck -Scope CurrentUser
```

### Development build
Install the main-branch build directly from this repository if you want the latest updates.

Check passwords and hashes against the [haveibeenpwned.com](https://haveibeenpwned.com) [Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) using PowerShell. Also supports third party equivalent APIs.
```powershell
# (optional) loosen execution policy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# install development build
iex (irm https://raw.githubusercontent.com/r0tifer/Get-Pwnd-PassCheck/main/instdev.ps1)
```

> [!WARNING]
> Make sure the download URL contains `raw.githubusercontent.com`. If you copy the
> standard GitHub `.../blob/main/...` link instead, GitHub returns an HTML page and
> PowerShell will throw parse errors like `Missing expression after unary operator '--'`
> when `Invoke-Expression` tries to run the HTML.

## Configure the module

1. Update the default configuration file created at `C:\PwndPassCheck\PwnedPassCheckSettings.psd1` (the module generates it the first time you run a command) or copy the template from the repository root and adjust the values:
   * `DomainName`, `DomainControllers`, and `BaseDN` for your Active Directory environment.
   * `HIBPApiKey` and `HIBPUserAgent` with the credentials issued to your organisation.
   * `NotifyUser` / `NotifyManager` toggles plus SMTP settings when you want email alerts.
   * `ManagersToNotify` and `ReportingFrequency` (Weekly or Monthly) for executive rollups.
2. Ensure the account running audits can replicate directory data and send email through the configured SMTP relay.
3. Keep the settings file in `C:\PwndPassCheck` for the built-in defaults or pass a custom location with `-SettingsPath` when executing commands.

> [!NOTE]
> When the module runs for the first time it creates `C:\PwndPassCheck`, copies the template settings file to that folder, and prompts you to update the values before rerunning any audits.

## Active Directory auditing workflow

```powershell
Import-Module PwnedPassCheck
Import-Module DSInternals

# Run the audit using the configured settings
$results = Get-PwnedADUserPassword -Verbose

# Filter to compromised accounts
$results | Where-Object IsPwned
```

During each run the command:

1. Pulls the configured settings and resolves the domain controllers to query.
2. Replicates enabled user accounts that have password hashes.
3. Queries the Have I Been Pwned API for each hash (respecting the `RequestPadding` setting when requested).
4. Writes the outcome to `C:\PwndPassCheck\PwnedPassCheckAuditLog.json` (or the path supplied with `-AuditLogPath`).

### Reviewing audit history

* `Get-PwnedAuditLog` – Returns audit entries for historical reporting.
* `Update-PwnedAuditLog` – Marks notification attempts or password change confirmations so repeated alerts are avoided.

## Email notifications and reporting

When notifications are enabled in the settings file:

* **User notifications** are sent the first time (and then at most once per day) the module finds a compromised password. The email includes guidance for resetting the password via **Ctrl+Alt+Del**, the date of discovery, and the total number of alerts sent.
* **Manager notifications** summarise exposure counts, last notification timestamps, and whether users have remediated their passwords. Reports can be generated weekly or monthly based on the `ReportingFrequency` setting.

Both notification types use the SMTP settings in the configuration file. Supply credentials for an account authorised to send emails on behalf of your security team, and verify any required TLS settings match your mail gateway.

## Automate daily checks and 1 PM notifications

Running the audit once and relying on manual follow-up defeats the purpose of automated remediation. Use a scheduled task to run `Get-PwnedADUserPassword` every day at **1:00 PM** so compromised accounts are detected and notifications are sent promptly.

### 1. Create an execution script

Save the following as `C:\Scripts\Run-PwnedPasswordAudit.ps1` (adjust paths to match your deployment):

```powershell
Import-Module PwnedPassCheck
Import-Module DSInternals

$settingsPath = 'C:\SecureConfig\PwnedPassCheckSettings.psd1'
$auditLogPath = 'C:\Logs\PwnedPassCheckAuditLog.json'

$results = Get-PwnedADUserPassword -SettingsPath $settingsPath -AuditLogPath $auditLogPath -Verbose
$results | Where-Object IsPwned | Out-File -FilePath 'C:\Logs\PwnedPassCheckLatest.txt'
```

The sample script loads the module, runs the audit with explicit settings/audit log paths, and records the latest list of exposed accounts. Because notification throttling is handled internally, running the task daily will only email users or managers when new activity occurs or the throttle window has expired.

### 2. Register a scheduled task that runs daily at 1:00 PM

Run the following commands from an elevated PowerShell session on the server that will host the automation. Replace the account details with a dedicated service account that has permission to replicate directory data and send mail.

```powershell
$action = New-ScheduledTaskAction -Execute 'pwsh.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Run-PwnedPasswordAudit.ps1"'

$trigger = New-ScheduledTaskTrigger -Daily -At 1:00PM

$principal = New-ScheduledTaskPrincipal -UserId 'CONTOSO\Svc-PwnedAudit' -LogonType Password -RunLevel Highest

Register-ScheduledTask -TaskName 'Pwned Password Audit' -Action $action -Trigger $trigger `
    -Principal $principal -Description 'Runs Get-PwnedADUserPassword daily and sends notifications at 1 PM.'
```

If the system only has Windows PowerShell, replace `pwsh.exe` with `powershell.exe`. After registration, supply the service account password when prompted. Confirm the task history to ensure it runs successfully and that emails arrive around 1 PM each day.

### 3. Validate the scheduled run

* Review `C:\Logs\PwnedPassCheckLatest.txt` and `PwnedPassCheckAuditLog.json` for new entries after the first run.
* Check the SMTP relay logs (or mailboxes) to ensure users and managers receive notifications when applicable.
* Periodically rerun `Get-PwnedAuditLog` manually to confirm password changes are being recorded.

## Quick start: ad-hoc password checks

```powershell
# Plain text (not recommended for real passwords)
Get-PwnedPassword 'password'

# SecureString input
$secure = Read-Host -Prompt 'Enter Password' -AsSecureString
Get-PwnedPassword $secure

# Check a known hash
Get-PwnedHash '70CCD9007338D6D81DD3B6271621B9CF9A97EA00'

# Test against an alternate API root and hash type
Get-PwnedPassword 'password' -ApiRoot 'https://pwnntlm.example.com/range/' -HashType NTLM
```

Each command returns the compromised hash count without ever sending the full password to the remote service thanks to k-anonymity.

## Credits

This fork builds on the outstanding work of [rmbolger](https://github.com/rmbolger) and Troy Hunt. Many commands, usage patterns, and installation instructions remain compatible with the upstream project.
