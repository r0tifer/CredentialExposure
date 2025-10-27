function Get-ExposureAuditLog {
    [CmdletBinding()]
    param(
        [string]$AuditLogPath,
        [string]$SamAccountName,
        [string]$AccountId
    )

    $environmentStatus = Initialize-PwnedPassCheckDataEnvironment
    if ($environmentStatus.DataDirectoryCreated) {
        Write-Verbose "Created data directory at '$($environmentStatus.DataDirectory)'."
    }

    if ($environmentStatus.AuditLogCreated) {
        Write-Verbose "Created default audit log at '$($environmentStatus.AuditLogPath)'."
    }

    if ($environmentStatus.SettingsFileCreated) {
        Write-Warning "A new settings file was created at '$($environmentStatus.SettingsPath)'. Update it before running password audits."
    }

    $moduleRoot = Split-Path -Parent $PSScriptRoot
    $repoRoot = Split-Path -Parent $moduleRoot

    $candidatePaths = @()
    if ($PSBoundParameters.ContainsKey('AuditLogPath')) {
        $candidatePaths += $AuditLogPath
    }

    $defaultAuditLogPaths = @(
        $script:DefaultAuditLogPath,
        (Join-Path -Path $repoRoot -ChildPath 'PwnedPassCheckAuditLog.json'),
        (Join-Path -Path $moduleRoot -ChildPath 'PwnedPassCheckAuditLog.json')
    ) | Where-Object { $_ }

    $candidatePaths += $defaultAuditLogPaths

    if ($PSBoundParameters.ContainsKey('AuditLogPath')) {
        $resolvedAuditLogPath = $AuditLogPath
    } else {
        $resolvedAuditLogPath = $candidatePaths | Where-Object { Test-Path -Path $_ } | Select-Object -First 1
        if (-not $resolvedAuditLogPath) {
            $resolvedAuditLogPath = $defaultAuditLogPaths | Select-Object -First 1
        }
    }

    if (-not $resolvedAuditLogPath) {
        Write-Verbose 'No audit log path could be resolved. Specify AuditLogPath to read audit data.'
        return
    }

    try {
        $auditLogState = Import-PwnedAuditLog -Path $resolvedAuditLogPath
    } catch {
        throw "Failed to read audit log from '$resolvedAuditLogPath': $_"
    }

    $entries = @()

    $parseDateTime = {
        param([Parameter(Mandatory = $false)] $Value)

        if ($null -eq $Value) {
            return $null
        }

        $stringValue = $Value.ToString().Trim()
        if (-not $stringValue) {
            return $null
        }

        try {
            return [datetime]::Parse($stringValue).ToUniversalTime()
        } catch {
            return $null
        }
    }

    foreach ($key in $auditLogState.Entries.Keys) {
        $entry = $auditLogState.Entries[$key]

        $userNotificationCount = 0
        if ($entry -is [System.Collections.IDictionary]) {
            if ($entry.Contains('UserNotificationCount')) {
                $countValue = $entry['UserNotificationCount']
                if ($countValue -is [int]) {
                    $userNotificationCount = $countValue
                } elseif ($null -ne $countValue) {
                    $parsedCount = 0
                    if ([int]::TryParse($countValue.ToString(), [ref]$parsedCount)) {
                        $userNotificationCount = $parsedCount
                    }
                }
            }
        } elseif ($entry.PSObject.Properties['UserNotificationCount']) {
            $countValue = $entry.PSObject.Properties['UserNotificationCount'].Value
            if ($countValue -is [int]) {
                $userNotificationCount = $countValue
            } elseif ($null -ne $countValue) {
                $parsedCount = 0
                if ([int]::TryParse($countValue.ToString(), [ref]$parsedCount)) {
                    $userNotificationCount = $parsedCount
                }
            }
        }

        if ($userNotificationCount -lt 0) {
            $userNotificationCount = 0
        }

        $entries += [pscustomobject]@{
            AccountId                        = $key
            SamAccountName                   = $entry.SamAccountName
            DistinguishedName                = $entry.DistinguishedName
            Domain                           = $entry.Domain
            LastAudit                        = & $parseDateTime -Value $entry.LastAudit
            SeenCount                        = [int]$entry.SeenCount
            IsPwned                          = [bool]$entry.IsPwned
            UserNotified                     = [bool]$entry.UserNotified
            UserNotifiedOn                   = & $parseDateTime -Value $entry.UserNotifiedOn
            UserNotificationCount            = [int]$userNotificationCount
            ManagerNotified                  = [bool]$entry.ManagerNotified
            ManagerNotifiedOn                = & $parseDateTime -Value $entry.ManagerNotifiedOn
            PasswordLastSet                  = & $parseDateTime -Value $entry.PasswordLastSet
            PasswordChangedAfterNotification = [bool]$entry.PasswordChangedAfterNotification
            PasswordChangedOn                = & $parseDateTime -Value $entry.PasswordChangedOn
            Hash                             = $entry.Hash
        }
    }

    if ($PSBoundParameters.ContainsKey('AccountId')) {
        $entries = $entries | Where-Object { $_.AccountId -eq $AccountId }
    }

    if ($PSBoundParameters.ContainsKey('SamAccountName')) {
        $entries = $entries | Where-Object { $_.SamAccountName -eq $SamAccountName }
    }

    return $entries
}
