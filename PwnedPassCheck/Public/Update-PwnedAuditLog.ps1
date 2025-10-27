function Update-ExposureAuditLog {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$AuditLogPath,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$AccountId,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$SamAccountName,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Nullable[datetime]]$UserNotifiedOn,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Nullable[datetime]]$ManagerNotifiedOn,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [bool]$UserNotified,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [bool]$ManagerNotified
    )

    begin {
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
            throw "No audit log path could be resolved. Specify AuditLogPath or use C:\PwndPassCheck\PwnedPassCheckAuditLog.json to update audit data."
        }

        try {
            $auditLogState = Import-PwnedAuditLog -Path $resolvedAuditLogPath
        } catch {
            throw "Failed to read audit log from '$resolvedAuditLogPath': $_"
        }

        $auditLogUpdated = $false
        $auditLogMetadata = $auditLogState.Metadata
        if (-not $auditLogMetadata) {
            $auditLogMetadata = New-Object System.Collections.Specialized.OrderedDictionary
        }

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
    }

    process {
        $targetKeys = @()
        if ($PSBoundParameters.ContainsKey('AccountId') -and $AccountId) {
            $targetKeys += $AccountId
        } elseif ($PSBoundParameters.ContainsKey('SamAccountName') -and $SamAccountName) {
            foreach ($key in $AuditLogState.Entries.Keys) {
                $entry = $AuditLogState.Entries[$key]
                if ($entry.SamAccountName -eq $SamAccountName) {
                    $targetKeys += $key
                }
            }
        }

        if (-not $targetKeys) {
            Write-Warning 'No matching audit log entry was found for the provided identifier.'
            return
        }

        foreach ($targetKey in $targetKeys) {
            if (-not $auditLogState.Entries.Contains($targetKey)) {
                Write-Warning "Audit log entry with AccountId '$targetKey' was not found."
                continue
            }

            $entry = $auditLogState.Entries[$targetKey]
            $shouldProcessTarget = $targetKey
            if ($entry.SamAccountName) {
                $shouldProcessTarget = "$($entry.SamAccountName) [$targetKey]"
            }

            if (-not $PSCmdlet.ShouldProcess($shouldProcessTarget, 'Update audit log entry')) {
                continue
            }

            if ($PSBoundParameters.ContainsKey('UserNotified')) {
                $entry.UserNotified = [bool]$UserNotified
                if ($UserNotified) {
                    if ($PSBoundParameters.ContainsKey('UserNotifiedOn') -and $null -ne $UserNotifiedOn) {
                        $entry.UserNotifiedOn = ([datetime]$UserNotifiedOn).ToUniversalTime().ToString('o')
                    } else {
                        $entry.UserNotifiedOn = (Get-Date).ToUniversalTime().ToString('o')
                    }
                } else {
                    $entry.UserNotifiedOn = $null
                }
            } elseif ($PSBoundParameters.ContainsKey('UserNotifiedOn') -and $null -ne $UserNotifiedOn) {
                $entry.UserNotifiedOn = ([datetime]$UserNotifiedOn).ToUniversalTime().ToString('o')
                if (-not $entry.UserNotified) {
                    $entry.UserNotified = $true
                }
            }

            if ($PSBoundParameters.ContainsKey('ManagerNotified')) {
                $entry.ManagerNotified = [bool]$ManagerNotified
                if ($ManagerNotified) {
                    if ($PSBoundParameters.ContainsKey('ManagerNotifiedOn') -and $null -ne $ManagerNotifiedOn) {
                        $entry.ManagerNotifiedOn = ([datetime]$ManagerNotifiedOn).ToUniversalTime().ToString('o')
                    } else {
                        $entry.ManagerNotifiedOn = (Get-Date).ToUniversalTime().ToString('o')
                    }
                } else {
                    $entry.ManagerNotifiedOn = $null
                }
            } elseif ($PSBoundParameters.ContainsKey('ManagerNotifiedOn') -and $null -ne $ManagerNotifiedOn) {
                $entry.ManagerNotifiedOn = ([datetime]$ManagerNotifiedOn).ToUniversalTime().ToString('o')
                if (-not $entry.ManagerNotified) {
                    $entry.ManagerNotified = $true
                }
            }

            $auditLogState.Entries[$targetKey] = $entry
            $auditLogUpdated = $true

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

            $result = [pscustomobject]@{
                AccountId                        = $targetKey
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

            Write-Output $result
        }
    }

    end {
        if ($auditLogUpdated) {
            try {
                Export-PwnedAuditLog -Path $resolvedAuditLogPath -Entries $auditLogState.Entries -Metadata $auditLogMetadata | Out-Null
            } catch {
                throw "Failed to persist audit log to '$resolvedAuditLogPath': $_"
            }
        }
    }
}
