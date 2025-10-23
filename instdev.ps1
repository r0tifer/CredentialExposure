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
    $url = 'https://github.com/r0tifer/Get-Pwnd-PassCheck/archive/refs/heads/main.zip'
    Write-Host "Downloading latest version of PwnedPassCheck from $url" -ForegroundColor Cyan
    $file = Join-Path ([system.io.path]::GetTempPath()) 'PwnedPassCheck.zip'
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
    $extractedRoot = Get-ChildItem -Path $installpath -Directory | Where-Object { $_.Name -like 'Get-Pwnd-PassCheck-*' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $extractedRoot) {
        throw "Unable to locate extracted repository folder in '$installpath'."
    }
    $sourceModulePath = Join-Path $extractedRoot.FullName 'PwnedPassCheck'
    if (-not (Test-Path $sourceModulePath)) {
        throw "The extracted repository in '$($extractedRoot.FullName)' does not contain a 'PwnedPassCheck' module folder."
    }
    Write-Host "Copying module from $sourceModulePath" -ForegroundColor Cyan
    Copy-Item $sourceModulePath $installpath -Recurse -Force
    Remove-Item $extractedRoot.FullName -Recurse -Force -Confirm:$false -EA SilentlyContinue
    Import-Module -Name PwnedPassCheck -Force
} else {
    # running locally
    Remove-Item "$installpath\PwnedPassCheck" -Recurse -Force -EA SilentlyContinue
    Copy-Item "$PSScriptRoot\PwnedPassCheck" $installpath -Recurse -Force
    # force re-load the module (assuming you're editing locally and want to see changes)
    Import-Module -Name PwnedPassCheck -Force
}
Write-Host 'Module has been installed' -ForegroundColor Green

try {
    $moduleInfo = Get-Module -Name PwnedPassCheck -ErrorAction Stop
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

    if ($environmentStatus.SettingsFileCreated) {
        Write-Warning "Update the settings file at '$($environmentStatus.SettingsPath)' before running password audits."
    }
} catch {
    Write-Warning "Unable to initialise the PwnedPassCheck data directory automatically: $_"
}

Get-Command -Module PwnedPassCheck
