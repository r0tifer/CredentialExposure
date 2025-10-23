#Requires -Version 3.0

# Get public and private function definition files.
$Public  = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )

# Dot source the files
foreach ($import in @($Public + $Private))
{
    try { . $import.fullname }
    catch {
        Write-Error -Message "Failed to import function $($import.fullname): $_"
    }
}

# Define common parameters for Invoke-WebRequest
$script:IWR_PARAMS = @{
    UserAgent = "PwnedPassCheck/3.0.0 PowerShell/$($PSVersionTable.PSVersion)"
    ErrorAction = 'Stop'
}

# Invoke-WebRequest in Windows PowerShell uses IE's DOM parser by default which
# can cause errors if IE is not installed or hasn't gone through the first-run
# sequence in a new profile. The -UseBasicParsing switch makes it use a PowerShell
# native parser instead and avoids those problems. In PowerShell Core 6+, the
# parameter has been deprecated because there is no IE DOM parser to use and all
# requests use the native parser by default. In order to future proof ourselves
# for the switch's eventual removal, we'll set it only if it actually exists.
if ('UseBasicParsing' -in (Get-Command Invoke-WebRequest).Parameters.Keys) {
    $script:IWR_PARAMS.UseBasicParsing = $true
}

if ('SslProtocol' -notin (Get-Command Invoke-WebRequest).Parameters.Keys) {
    # make sure we have recent TLS versions enabled for Desktop edition
    $currentMaxTls = [Math]::Max([Net.ServicePointManager]::SecurityProtocol.value__,[Net.SecurityProtocolType]::Tls.value__)
    $newTlsTypes = [enum]::GetValues('Net.SecurityProtocolType') | Where-Object { $_ -gt $currentMaxTls }
    $newTlsTypes | ForEach-Object {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $_
    }
}

$script:ModuleRoot = $PSScriptRoot
$script:RepoRoot = Split-Path -Parent $script:ModuleRoot

function Get-PwnedPassCheckDefaultDirectory {
    $systemDrive = $env:SystemDrive
    if (-not $systemDrive -and $IsWindows) {
        try {
            $systemDirectory = [Environment]::SystemDirectory
            if ($systemDirectory) {
                $systemDrive = Split-Path -Path $systemDirectory -Qualifier
            }
        } catch {
            $systemDrive = $null
        }
    }

    if ($systemDrive) {
        return Join-Path -Path $systemDrive -ChildPath 'PwndPassCheck'
    }

    if ($HOME) {
        return Join-Path -Path $HOME -ChildPath 'PwndPassCheck'
    }

    return Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'PwndPassCheck'
}

$script:DefaultDataDirectory = Get-PwnedPassCheckDefaultDirectory
$script:DefaultSettingsPath = Join-Path -Path $script:DefaultDataDirectory -ChildPath 'PwnedPassCheckSettings.psd1'
$script:DefaultAuditLogPath = Join-Path -Path $script:DefaultDataDirectory -ChildPath 'PwnedPassCheckAuditLog.json'
$script:DefaultServiceRunnerPath = Join-Path -Path $script:DefaultDataDirectory -ChildPath 'PwnedPassCheckServiceRunner.ps1'
$script:DefaultServiceAppSettingsPath = Join-Path -Path $script:DefaultDataDirectory -ChildPath 'appsettings.json'
$script:DefaultServiceProjectPath = Join-Path -Path $script:DefaultDataDirectory -ChildPath 'Service'
$script:DefaultInstallerScriptPath = Join-Path -Path $script:DefaultDataDirectory -ChildPath 'instdev.ps1'

function Initialize-PwnedPassCheckDataEnvironment {
    $status = [pscustomobject]@{
        DataDirectoryCreated   = $false
        SettingsFileCreated    = $false
        AuditLogCreated        = $false
        DataDirectory          = $script:DefaultDataDirectory
        SettingsPath           = $script:DefaultSettingsPath
        AuditLogPath           = $script:DefaultAuditLogPath
        SettingsTemplateSource = $null
        ServiceRunnerPath      = $script:DefaultServiceRunnerPath
        ServiceRunnerCopied    = $false
        ServiceRunnerSource    = $null
        ServiceAppSettingsPath = $script:DefaultServiceAppSettingsPath
        ServiceAppSettingsCopied = $false
        ServiceAppSettingsSource = $null
        ServiceProjectPath     = $script:DefaultServiceProjectPath
        ServiceProjectCopied   = $false
        ServiceProjectSource   = $null
        ServiceProjectPresent  = Test-Path -Path $script:DefaultServiceProjectPath -PathType Container
        InstallerScriptPath    = $script:DefaultInstallerScriptPath
        InstallerScriptCopied  = $false
        InstallerScriptSource  = $null
        InstallerScriptPresent = Test-Path -Path $script:DefaultInstallerScriptPath -PathType Leaf
    }

    if (-not (Test-Path -Path $script:DefaultDataDirectory)) {
        try {
            New-Item -Path $script:DefaultDataDirectory -ItemType Directory -Force | Out-Null
            $status.DataDirectoryCreated = $true
        } catch {
            throw "Unable to create the data directory '$($script:DefaultDataDirectory)': $_"
        }
    }

    if (-not (Test-Path -Path $script:DefaultSettingsPath)) {
        $templateCandidates = @(
            (Join-Path -Path $script:RepoRoot -ChildPath 'PwnedPassCheckSettings.psd1'),
            (Join-Path -Path $script:ModuleRoot -ChildPath 'PwnedPassCheckSettings.psd1')
        ) | Where-Object { $_ -and (Test-Path -Path $_) }

        if ($templateCandidates) {
            $templateSource = $templateCandidates | Select-Object -First 1
            try {
                Copy-Item -Path $templateSource -Destination $script:DefaultSettingsPath -Force
                $status.SettingsTemplateSource = $templateSource
            } catch {
                throw "Failed to copy default settings file from '$templateSource' to '$($script:DefaultSettingsPath)': $_"
            }
        } else {
            try {
                $defaultSettingsContent = @'
@{
    # HIBPApiKey: Provide the 32-character hexadecimal API key issued by Have I Been Pwned for authenticated API requests.
    HIBPApiKey = ""

    # HIBPUserAgent: Provide the contact email address or descriptive user agent required by the HIBP API terms.
    HIBPUserAgent = ""

    # AD Domain: Provide the fully qualified domain name (FQDN) for your Active Directory environment (e.g., corp.example.com).
    ADDomain = "corp.example.com"

    # Domain Controllers: Provide one or more fully qualified domain controller hostnames separated by commas (e.g., "dc1.corp.example.com, dc2.corp.example.com").
    DomainControllers = "dc1.corp.example.com"

    # Notify User: Set to $true to email affected users when their password is detected; otherwise set to $false.
    NotifyUser = $false

    # Notify Manager: Set to $true to notify the user's manager about detected passwords; otherwise set to $false.
    NotifyManager = $false

    # ManagersToNotify: (Optional) Additional manager email addresses to receive alerts, separated by commas. Leave blank to disable.
    ManagersToNotify = ""

    # HIBPApiRoot: (Optional) Override the Have I Been Pwned Pwned Passwords API endpoint. Leave blank to use the module default.
    HIBPApiRoot = ""

    # HIBPRequestPadding: Set to $true to request padded API responses for additional privacy; otherwise set to $false.
    HIBPRequestPadding = $false

    # HIBPNoModeQueryString: Set to $true to prevent the mode=ntlm query string from being added when checking NTLM hashes.
    HIBPNoModeQueryString = $false

    # ReportingFrequency: Set to 'Weekly' or 'Monthly' to control how often manager summary emails are sent when NotifyManager is $true.
    ReportingFrequency = ""

    # SmtpServer: (Required when NotifyUser or NotifyManager is $true) Host name or IP address of the SMTP server used to send notifications.
    SmtpServer = ""

    # FromAddress: (Required when NotifyUser or NotifyManager is $true) Email address that will appear in the From field of notifications.
    FromAddress = ""

    # EmailUserAccount: (Required when NotifyUser or NotifyManager is $true) Username or email of the account used to send notifications.
    EmailUserAccount = ""

    # EmailUserPassword: (Required when NotifyUser or NotifyManager is $true) Password for the notification email account.
    EmailUserPassword = ""

    # SendingPort: (Required when NotifyUser or NotifyManager is $true) SMTP port number used for sending notifications (e.g., 25, 465, 587).
    SendingPort = ""

    # EncryptionType: (Required when NotifyUser or NotifyManager is $true) Accepted values: 'None', 'StartTLS', or 'SSL/TLS'.
    EncryptionType = ""
}
'@
                $defaultSettingsContent | Set-Content -Path $script:DefaultSettingsPath -Encoding UTF8
            } catch {
                throw "Failed to create default settings file at '$($script:DefaultSettingsPath)': $_"
            }
        }

        $status.SettingsFileCreated = $true
    }

    if (-not (Test-Path -Path $script:DefaultAuditLogPath)) {
        try {
            $emptyEntries = New-Object System.Collections.Specialized.OrderedDictionary
            $emptyMetadata = New-Object System.Collections.Specialized.OrderedDictionary
            Export-PwnedAuditLog -Path $script:DefaultAuditLogPath -Entries $emptyEntries -Metadata $emptyMetadata | Out-Null
            $status.AuditLogCreated = $true
        } catch {
            throw "Failed to create default audit log at '$($script:DefaultAuditLogPath)': $_"
        }
    }

    $serviceRunnerCandidates = @(
        (Join-Path -Path $script:RepoRoot -ChildPath 'Service\PwnedPassCheckServiceRunner.ps1'),
        (Join-Path -Path $script:ModuleRoot -ChildPath 'Service\PwnedPassCheckServiceRunner.ps1')
    ) | Where-Object { $_ -and (Test-Path -Path $_) }

    if ($serviceRunnerCandidates) {
        $status.ServiceRunnerSource = $serviceRunnerCandidates | Select-Object -First 1

        if (-not (Test-Path -Path $script:DefaultServiceRunnerPath)) {
            try {
                Copy-Item -Path $status.ServiceRunnerSource -Destination $script:DefaultServiceRunnerPath -Force
                $status.ServiceRunnerCopied = $true
            } catch {
                throw "Failed to copy service runner script from '$($status.ServiceRunnerSource)' to '$($script:DefaultServiceRunnerPath)': $_"
            }
        }
    } elseif (-not (Test-Path -Path $script:DefaultServiceRunnerPath)) {
        Write-Warning "Unable to locate a template for 'PwnedPassCheckServiceRunner.ps1'. Ensure the module includes the service assets."
    }

    $serviceAppSettingsCandidates = @(
        (Join-Path -Path $script:RepoRoot -ChildPath 'Service\appsettings.json'),
        (Join-Path -Path $script:ModuleRoot -ChildPath 'Service\appsettings.json')
    ) | Where-Object { $_ -and (Test-Path -Path $_) }

    if ($serviceAppSettingsCandidates) {
        $status.ServiceAppSettingsSource = $serviceAppSettingsCandidates | Select-Object -First 1

        if (-not (Test-Path -Path $script:DefaultServiceAppSettingsPath)) {
            try {
                Copy-Item -Path $status.ServiceAppSettingsSource -Destination $script:DefaultServiceAppSettingsPath -Force
                $status.ServiceAppSettingsCopied = $true
            } catch {
                throw "Failed to copy default service settings from '$($status.ServiceAppSettingsSource)' to '$($script:DefaultServiceAppSettingsPath)': $_"
            }
        }
    } elseif (-not (Test-Path -Path $script:DefaultServiceAppSettingsPath)) {
        Write-Warning "Unable to locate a template for 'appsettings.json'. Ensure the module includes the service assets."
    }

    $serviceProjectCandidates = @(
        (Join-Path -Path $script:RepoRoot -ChildPath 'Service'),
        (Join-Path -Path $script:ModuleRoot -ChildPath 'Service')
    ) | Where-Object {
        $_ -and (Test-Path -Path $_ -PathType Container) -and (Test-Path -Path (Join-Path -Path $_ -ChildPath 'PwnedPassCheckService.csproj'))
    }

    if ($serviceProjectCandidates) {
        $status.ServiceProjectSource = $serviceProjectCandidates | Select-Object -First 1

        if (-not $status.ServiceProjectPresent) {
            try {
                Copy-Item -Path $status.ServiceProjectSource -Destination $script:DefaultServiceProjectPath -Recurse -Force
                $status.ServiceProjectCopied = $true
                $status.ServiceProjectPresent = $true
            } catch {
                throw "Failed to copy service project from '$($status.ServiceProjectSource)' to '$($script:DefaultServiceProjectPath)': $_"
            }
        }
    } elseif (-not $status.ServiceProjectPresent) {
        Write-Warning "Unable to locate the service project. Clone the repository to access the Windows service source."
    }

    $installerScriptCandidates = @(
        (Join-Path -Path $script:RepoRoot -ChildPath 'instdev.ps1'),
        (Join-Path -Path $script:ModuleRoot -ChildPath '..\instdev.ps1'),
        (Join-Path -Path $script:ModuleRoot -ChildPath 'instdev.ps1')
    ) | Where-Object { $_ -and (Test-Path -Path $_ -PathType Leaf) }

    if ($installerScriptCandidates) {
        $status.InstallerScriptSource = $installerScriptCandidates | Select-Object -First 1

        if (-not $status.InstallerScriptPresent) {
            try {
                Copy-Item -Path $status.InstallerScriptSource -Destination $script:DefaultInstallerScriptPath -Force
                $status.InstallerScriptCopied = $true
                $status.InstallerScriptPresent = $true
            } catch {
                throw "Failed to copy installer script from '$($status.InstallerScriptSource)' to '$($script:DefaultInstallerScriptPath)': $_"
            }
        }
    } elseif (-not $status.InstallerScriptPresent) {
        Write-Warning "Unable to locate 'instdev.ps1'. Download the installer script manually if you need to redeploy the module."
    }

    return $status
}
