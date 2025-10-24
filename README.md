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
Install the main-branch build directly from this repository if you want the latest updates.

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

1. Update the default configuration file created at `C:\PwndPassCheck\PwnedPassCheckSettings.psd1` (the module generates on first run):
   * `DomainName`, `DomainControllers`, and `BaseDN` for your Active Directory environment.
   * `HIBPApiKey` and `HIBPUserAgent` with the credentials issued to your organisation.
   * `NotifyUser` / `NotifyManager` toggles plus SMTP settings when you want email alerts.
   * Generate the `EmailUserPassword` value with `New-PwnedNotificationPasswordSecret` while signed in as the service account that will run the module, then paste the encrypted output into the settings file.
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

# Filter to detected accounts
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

Both notification types use the SMTP settings in the configuration file. Supply credentials for an account authorised to send emails on behalf of your security team, and verify that any required TLS settings match your mail gateway.

> [!IMPORTANT]
> `EmailUserPassword` must contain the encrypted output from `New-PwnedNotificationPasswordSecret`. Run the command while signed in as the service account (or scheduled-task identity) that will execute the module so DPAPI can decrypt the value at runtime.

# Automate daily checks and 1 PM notifications

Running the audit once and relying on manual follow-up defeats the purpose of automated remediation. Get-Pwnd-PassCheck can run as a Windows Service or a scheduled task, automatically executing `Get-PwnedADUserPassword` every day at **1:00 PM** (or the configured frequency in PwndPassCheckSettings.psd1) to detect unsafe accounts and send notifications promptly.

## Run Get-Pwnd-PassCheck as a Windows service

**Service layout**
   - Always run `instdev.ps1` on the machine that will host the Windows service. This installs the PowerShell module and seeds `C:\PwndPassCheck` with everything the worker expects (`appsettings.json`, `PwnedPassCheckServiceRunner.ps1`, the module settings file, an empty audit log, and a copy of the `Service` project). The installer script itself is also saved to `C:\PwndPassCheck\instdev.ps1` so you can rerun it locally if needed.
   - The worker service loads configuration exclusively from `C:\PwndPassCheck\appsettings.json` and executes `C:\PwndPassCheck\PwnedPassCheckServiceRunner.ps1`. Keep every runtime asset (settings file, audit log, runner script) in that directory unless you explicitly reconfigure them in `appsettings.json`.
   - The copy of the `Service` project that is seeded under `C:\PwndPassCheck\Service` omits `appsettings.json`; the canonical configuration file lives at `C:\PwndPassCheck\appsettings.json`, which the service uses directly.
   - If you customise any of those files, update both the live copies under `C:\PwndPassCheck` and the templates in `PwnedPassCheck\Service\` so future installs stay in sync.

**Build or obtain the service binary**
   - The PowerShell module delivered by `instdev.ps1` does **not** include the compiled Windows service executable. Either download a pre-built release or publish it yourself.
   - If you used `instdev.ps1`, the source lives under `C:\PwndPassCheck\Service`; run `dotnet publish .\PwnedPassCheckService.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true` from that folder.
   - When working from a cloned repository, run `dotnet publish .\Service\PwnedPassCheckService.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true` at the repo root.
   - The compiled binaries land under the project's `bin\Release\net6.0-windows\win-x64\publish` directory.

**Deploy the payload**
   - Create a target folder such as `C:\Program Files\PwnedPassCheckService`.
   - Copy the entire contents of the `publish` directory into that folder. These files include `PwnedPassCheckService.exe` and companions for running as a Windows service.
   - Do **not** move `appsettings.json` or `PwnedPassCheckServiceRunner.ps1` out of `C:\PwndPassCheck`; the service reads the live configuration and scripts from that directory. If you overwrite them during publishing, rerun `instdev.ps1` to reseed or copy your customised versions back into place.

**Edit the service settings**
   - Update `C:\PwndPassCheck\appsettings.json` before registering the service. The worker reloads changes automatically while running.
   - Set `Service:PwshPath` to the full path of `pwsh.exe` (use `powershell.exe` if PowerShell 5.1 is required).
   - Confirm `Service:ServiceScriptPath`, `Service:SettingsPath`, and `Service:AuditLogPath` point at the assets in `C:\PwndPassCheck` (change them only if you relocate the directory and update all references together).
   - Adjust `Service:RunIntervalMinutes` to the cadence you want (minimum 5, default 30) and flip `Verbose` to `true` if you want detailed logging.

**Confirm the runner script**
   - Update `PwnedPassCheckServiceRunner.ps1` if you need additional parameters or preprocessing.
   - Confirm the service account has access to the `PwnedPassCheck` and `DSInternals` modules and to the configuration/audit paths.

**Register the Windows service (elevated PowerShell)**
   - `$serviceExe = 'C:\Program Files\PwnedPassCheckService\PwnedPassCheckService.exe'`
   - `New-Service -Name 'PwnedPassCheckService' -BinaryPathName "`"$serviceExe`"" -DisplayName 'Pwned Password Auditor' -Description 'Runs Get-PwnedADUserPassword on a fixed interval.' -StartupType Automatic -Credential (Get-Credential)`
   - `sc.exe failure PwnedPassCheckService reset= 86400 actions= restart/60000/restart/60000/""/0` (optional: auto-restart on failure)

**Start and validate**
   - `Start-Service PwnedPassCheckService`
   - Check `Get-Service PwnedPassCheckService` for `Running`.
   - Review `Get-WinEvent -LogName Application -ProviderName 'PwnedPassCheckService' -MaxEvents 20` for status messages.
   - Confirm the audit log and notification outputs update on the configured interval.

**Operational tips**
   - Use `Restart-Service PwnedPassCheckService` after any config or script change.
   - Rotate the service account password and reapply with `sc.exe config PwnedPassCheckService obj= "DOMAIN\Svc-Pwned" password= "NewPassword"` when required.
   - Keep the PowerShell modules patched and re-publish the service after repo updates.

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
