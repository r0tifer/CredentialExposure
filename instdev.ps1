#Requires -Version 3.0

# set the user module path based on edition and platform
if ('PSEdition' -notin $PSVersionTable.Keys -or $PSVersionTable.PSEdition -eq 'Desktop') {
    $installpath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules'
} else {
    if ($IsWindows) {
        $installpath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules'
    } else {
        $installpath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) '.local/share/powershell/Modules'
    }
}

# create user-specific modules folder if it doesn't exist
New-Item -ItemType Directory -Force -Path $installpath | out-null

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

function Copy-PwnedPassCheckServiceProject {
    param(
        [Parameter(Mandatory)]
        [string]$SourceRoot
    )

    $serviceSource = Join-Path -Path $SourceRoot -ChildPath 'Service'
    if (-not (Test-Path -Path $serviceSource -PathType Container)) {
        return
    }

    if (-not (Test-Path -Path (Join-Path -Path $serviceSource -ChildPath 'PwnedPassCheckService.csproj'))) {
        return
    }

    $dataDirectory = Get-PwnedPassCheckDefaultDirectory
    if (-not (Test-Path -Path $dataDirectory -PathType Container)) {
        New-Item -Path $dataDirectory -ItemType Directory -Force | Out-Null
    }

    $destination = Join-Path -Path $dataDirectory -ChildPath 'Service'
    if (Test-Path -Path $destination -PathType Container) {
        Write-Host "Service project already present at '$destination'." -ForegroundColor DarkGray
        return
    }

    Copy-Item -Path $serviceSource -Destination $destination -Recurse -Force

    $serviceAppSettingsPath = Join-Path -Path $destination -ChildPath 'appsettings.json'
    if (Test-Path -Path $serviceAppSettingsPath -PathType Leaf) {
        Remove-Item -Path $serviceAppSettingsPath -Force -ErrorAction SilentlyContinue
    }

    foreach ($buildFolder in @('bin', 'obj', '.vs')) {
        $buildPath = Join-Path -Path $destination -ChildPath $buildFolder
        if (Test-Path -Path $buildPath -PathType Container) {
            Remove-Item -Path $buildPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Copied service project to '$destination'." -ForegroundColor Green
}

function Copy-PwnedPassCheckInstaller {
    param(
        [Parameter(Mandatory)]
        [string]$SourceRoot
    )

    $dataDirectory = Get-PwnedPassCheckDefaultDirectory
    if (-not (Test-Path -Path $dataDirectory -PathType Container)) {
        New-Item -Path $dataDirectory -ItemType Directory -Force | Out-Null
    }

    $sourceScript = Join-Path -Path $SourceRoot -ChildPath 'instdev.ps1'
    if (-not (Test-Path -Path $sourceScript -PathType Leaf)) {
        return
    }

    $destinationScript = Join-Path -Path $dataDirectory -ChildPath 'instdev.ps1'
    Copy-Item -Path $sourceScript -Destination $destinationScript -Force
    Write-Host "Copied installer script to '$destinationScript'." -ForegroundColor Green
}

if ([String]::IsNullOrWhiteSpace($PSScriptRoot)) {
    # likely running from online

    # GitHub now requires TLS 1.2
    # https://blog.github.com/2018-02-23-weak-cryptographic-standards-removed/
    $currentMaxTls = [Math]::Max([Net.ServicePointManager]::SecurityProtocol.value__,[Net.SecurityProtocolType]::Tls.value__)
    $newTlsTypes = [enum]::GetValues('Net.SecurityProtocolType') | Where-Object { $_ -gt $currentMaxTls }
    $newTlsTypes | ForEach-Object {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $_
    }

    # download and extract
    $webclient = New-Object System.Net.WebClient
    $url = 'https://github.com/r0tifer/CredentialExposure/archive/refs/heads/main.zip'
    Write-Host "Downloading latest version of CredentialExposure from $url" -ForegroundColor Cyan
    $file = Join-Path ([system.io.path]::GetTempPath()) 'CredentialExposure.zip'
    $webclient.DownloadFile($url,$file)
    Write-Host "File saved to $file" -ForegroundColor Green

    # try to use Expand-Archive if it exists, otherwise assume Desktop
    # edition and use COM
    Write-Host "Uncompressing the Zip file to $($installpath)" -ForegroundColor Cyan
    if (Get-Command Expand-Archive -EA SilentlyContinue) {
        Expand-Archive $file -DestinationPath $installpath -Force
    } else {
        $shell_app=new-object -com shell.application
        $zip_file = $shell_app.namespace($file)
        $destination = $shell_app.namespace($installpath)
        $destination.Copyhere($zip_file.items(), 0x10)
    }

    Write-Host "Removing any old copy" -ForegroundColor Cyan
    Remove-Item "$installpath\PwnedPassCheck" -Recurse -Force -EA SilentlyContinue
    $extractedRoot = Get-ChildItem -Path $installpath -Directory | Where-Object { $_.Name -like 'CredentialExposure-*' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $extractedRoot) {
        throw "Unable to locate extracted repository folder in '$installpath'."
    }
    $sourceModulePath = Join-Path $extractedRoot.FullName 'PwnedPassCheck'
    if (-not (Test-Path $sourceModulePath)) {
        throw "The extracted repository in '$($extractedRoot.FullName)' does not contain a 'PwnedPassCheck' module folder."
    }
    Write-Host "Copying module from $sourceModulePath" -ForegroundColor Cyan
    $destModulePath = Join-Path $installpath 'CredExposureCheck'
    if (Test-Path $destModulePath) { Remove-Item $destModulePath -Recurse -Force -EA SilentlyContinue }
    Copy-Item $sourceModulePath $destModulePath -Recurse -Force
    # Ensure a manifest with the destination module name exists for Import-Module by name
    $srcManifest = Join-Path $destModulePath 'PwnedPassCheck.psd1'
    $dstManifest = Join-Path $destModulePath 'CredExposureCheck.psd1'
    if (Test-Path $srcManifest) { Copy-Item $srcManifest $dstManifest -Force }
    Copy-PwnedPassCheckServiceProject -SourceRoot $extractedRoot.FullName
    Copy-PwnedPassCheckInstaller -SourceRoot $extractedRoot.FullName
    Remove-Item $extractedRoot.FullName -Recurse -Force -Confirm:$false -EA SilentlyContinue
    Import-Module -Name CredExposureCheck -Force
} else {
    # running locally
    Remove-Item "$installpath\CredExposureCheck" -Recurse -Force -EA SilentlyContinue
    $destModulePath = Join-Path $installpath 'CredExposureCheck'
    Copy-Item "$PSScriptRoot\PwnedPassCheck" $destModulePath -Recurse -Force
    $srcManifest = Join-Path $destModulePath 'PwnedPassCheck.psd1'
    $dstManifest = Join-Path $destModulePath 'CredExposureCheck.psd1'
    if (Test-Path $srcManifest) { Copy-Item $srcManifest $dstManifest -Force }
    Copy-PwnedPassCheckServiceProject -SourceRoot $PSScriptRoot
    Copy-PwnedPassCheckInstaller -SourceRoot $PSScriptRoot
    # force re-load the module (assuming you're editing locally and want to see changes)
    Import-Module -Name CredExposureCheck -Force
}
Write-Host 'Module has been installed' -ForegroundColor Green

function Ensure-DSInternalsModule {
    param()

    if (-not $IsWindows) {
        return
    }

    if (Get-Command -Name Get-ADReplAccount -ErrorAction SilentlyContinue) {
        return
    }

    Write-Warning "The DSInternals module is required for Active Directory replication (Get-ADReplAccount)."
    try {
        # Prompt user for consent to install
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes','Install DSInternals for the current user from the PowerShell Gallery.'
        $no  = New-Object System.Management.Automation.Host.ChoiceDescription '&No','Skip installation.'
        $choice = $Host.UI.PromptForChoice('DSInternals Required', 'DSInternals is not installed. Would you like to install it now?', @($yes,$no), 0)
        if ($choice -ne 0) {
            Write-Host 'Skipping DSInternals installation. You can install it later with: Install-Module DSInternals -Scope CurrentUser' -ForegroundColor Yellow
            return
        }

        # Ensure TLS 1.2+ for gallery downloads
        $currentMaxTls = [Math]::Max([Net.ServicePointManager]::SecurityProtocol.value__,[Net.SecurityProtocolType]::Tls.value__)
        $newTlsTypes = [enum]::GetValues('Net.SecurityProtocolType') | Where-Object { $_ -gt $currentMaxTls }
        $newTlsTypes | ForEach-Object {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $_
        }

        # Make sure PowerShellGet is available
        if (-not (Get-Module -ListAvailable -Name PowerShellGet)) {
            Import-Module PowerShellGet -ErrorAction SilentlyContinue | Out-Null
        }

        # Ensure PSGallery is registered
        $psGallery = $null
        try { $psGallery = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop } catch {}
        if (-not $psGallery) {
            try { Register-PSRepository -Default -ErrorAction Stop } catch {}
        }

        # Install DSInternals for current user
        Write-Host 'Installing DSInternals module (CurrentUser scope)...' -ForegroundColor Cyan
        try {
            Install-Module -Name DSInternals -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        } catch {
            Write-Warning "Failed to install DSInternals from the PowerShell Gallery: $_"
        }

        # Import the module if available now
        try {
            Import-Module -Name DSInternals -Force -ErrorAction Stop
        } catch {
            Write-Warning "DSInternals could not be imported: $_"
        }

        if (Get-Command -Name Get-ADReplAccount -ErrorAction SilentlyContinue) {
            Write-Host 'DSInternals is installed and ready.' -ForegroundColor Green
        } else {
            Write-Warning 'Get-ADReplAccount is still not available. Install the DSInternals module and try again.'
        }
    } catch {
        Write-Warning "An error occurred while checking/installing DSInternals: $_"
    }
}

try {
    $moduleInfo = Get-Module -Name CredExposureCheck -ErrorAction Stop
    $environmentStatus = $moduleInfo.Invoke({ Initialize-PwnedPassCheckDataEnvironment })

    if ($environmentStatus.DataDirectory) {
        if ($environmentStatus.DataDirectoryCreated) {
            Write-Host "Created data directory at '$($environmentStatus.DataDirectory)'." -ForegroundColor Green
        } elseif (Test-Path -Path $environmentStatus.DataDirectory) {
            Write-Host "Data directory already present at '$($environmentStatus.DataDirectory)'." -ForegroundColor DarkGray
        }
    }

    if ($environmentStatus.SettingsPath) {
        if ($environmentStatus.SettingsFileCreated) {
            Write-Host "Copied default settings to '$($environmentStatus.SettingsPath)'." -ForegroundColor Green
        } elseif (Test-Path -Path $environmentStatus.SettingsPath) {
            Write-Host "Settings file already present at '$($environmentStatus.SettingsPath)'." -ForegroundColor DarkGray
        }
    }

    if ($environmentStatus.AuditLogPath) {
        if ($environmentStatus.AuditLogCreated) {
            Write-Host "Created empty audit log at '$($environmentStatus.AuditLogPath)'." -ForegroundColor Green
        } elseif (Test-Path -Path $environmentStatus.AuditLogPath) {
            Write-Host "Audit log already present at '$($environmentStatus.AuditLogPath)'." -ForegroundColor DarkGray
        }
    }

    if ($environmentStatus.ServiceRunnerPath) {
        if ($environmentStatus.ServiceRunnerCopied) {
            Write-Host "Copied service runner script to '$($environmentStatus.ServiceRunnerPath)'." -ForegroundColor Green
        } elseif (Test-Path -Path $environmentStatus.ServiceRunnerPath) {
            Write-Host "Service runner script already present at '$($environmentStatus.ServiceRunnerPath)'." -ForegroundColor DarkGray
        }
    }

    if ($environmentStatus.ServiceAppSettingsPath) {
        if ($environmentStatus.ServiceAppSettingsCopied) {
            Write-Host "Copied default service settings to '$($environmentStatus.ServiceAppSettingsPath)'." -ForegroundColor Green
        } elseif (Test-Path -Path $environmentStatus.ServiceAppSettingsPath) {
            Write-Host "Service settings already present at '$($environmentStatus.ServiceAppSettingsPath)'." -ForegroundColor DarkGray
        }
    }

    if ($environmentStatus.ServiceProjectPath) {
        if ($environmentStatus.ServiceProjectCopied) {
            Write-Host "Copied service project to '$($environmentStatus.ServiceProjectPath)'." -ForegroundColor Green
        } elseif ($environmentStatus.ServiceProjectPresent) {
            Write-Host "Service project already present at '$($environmentStatus.ServiceProjectPath)'." -ForegroundColor DarkGray
        } else {
            Write-Warning "Service project not found at '$($environmentStatus.ServiceProjectPath)'."
        }
    }

    if ($environmentStatus.InstallerScriptPath) {
        if ($environmentStatus.InstallerScriptCopied) {
            Write-Host "Copied installer script to '$($environmentStatus.InstallerScriptPath)'." -ForegroundColor Green
        } elseif ($environmentStatus.InstallerScriptPresent) {
            Write-Host "Installer script already present at '$($environmentStatus.InstallerScriptPath)'." -ForegroundColor DarkGray
        } else {
            Write-Warning "Installer script not found at '$($environmentStatus.InstallerScriptPath)'."
        }
    }

    if ($environmentStatus.SettingsFileCreated) {
        Write-Warning "Update the settings file at '$($environmentStatus.SettingsPath)' before running password audits."
    }
} catch {
    Write-Warning "Unable to initialise the PwnedPassCheck data directory automatically: $_"
}

# Offer to install DSInternals if missing
Ensure-DSInternalsModule

Get-Command -Module CredExposureCheck
