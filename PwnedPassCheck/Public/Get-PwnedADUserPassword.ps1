<#
.SYNOPSIS
    Retrieves Active Directory user accounts with passwords and checks them against the Pwned Passwords API.

.DESCRIPTION
    Get-PwnedADUserPassword loads domain auditing settings from the PwnedPassCheckSettings.psd1 configuration file, replicates active
    user accounts that have an assigned password hash, and queries the Have I Been Pwned Pwned Passwords API for each discovered password
    hash. Results include the seen count and whether a password has been exposed.

.PARAMETER SettingsPath
    Overrides the default path to the PwnedPassCheckSettings.psd1 configuration file. The default
    configuration is stored in C:\PwndPassCheck\PwnedPassCheckSettings.psd1.

.PARAMETER ApiRoot
    Overrides the default Pwned Passwords API endpoint.

.PARAMETER ApiKey
    Overrides the API key sent to the Have I Been Pwned API. When omitted, the command uses the value from the settings file if provided.

.PARAMETER UserAgent
    Overrides the user agent sent to the Have I Been Pwned API. When omitted, the command uses the value from the settings file if provided.

.PARAMETER RequestPadding
    Adds the Add-Padding header to API requests when specified.

.PARAMETER NoModeQueryString
    Prevents the NTLM mode query string from being added to API requests.

.PARAMETER AuditLogPath
    Specifies the path to the audit log JSON file. When not provided, the command uses
    C:\PwndPassCheck\PwnedPassCheckAuditLog.json, creating the file if necessary.

.OUTPUTS
    PSCustomObject representing each processed Active Directory user account.

.EXAMPLE
    PS C:\> Get-PwnedADUserPassword -Verbose

    Uses the configured domain controllers, enumerates active domain users with passwords, and checks each password hash against the Have I Been Pwned API.

.NOTES
    Requires the DSInternals module for Get-ADReplAccount.
#>
function Get-PwnedADUserPassword {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$SettingsPath,
        [ValidateNotNullOrEmpty()]
        [string]$ApiRoot = "https://api.pwnedpasswords.com/range/",
        [string]$ApiKey,
        [string]$UserAgent,
        [switch]$RequestPadding,
        [switch]$NoModeQueryString,
        [string]$AuditLogPath
    )

    begin {
        if (-not (Get-Command -Name Get-PwnedHash -Module PwnedPassCheck -ErrorAction SilentlyContinue)) {
            throw "Get-PwnedHash from the PwnedPassCheck module must be available."
        }

        if (-not (Get-Command -Name Get-ADReplAccount -ErrorAction SilentlyContinue)) {
            throw "Get-ADReplAccount was not found. Install and import the DSInternals module."
        }

        $getDomainAccounts = {
            param(
                [Parameter(Mandatory)]
                [string]$DomainController
            )

            try {
                $accounts = Get-ADReplAccount -All -Server $DomainController -ErrorAction Stop
            } catch {
                Write-Warning "Failed to replicate accounts from '$DomainController': $_"
                return @()
            }

            return $accounts | Where-Object {
                $_.SamAccountType -eq 'User' -and
                $_.Enabled -eq $true -and
                $_.Deleted -eq $false -and
                $_.NTHash
            }
        }

        $convertNTHashToString = {
            param(
                [Parameter(Mandatory)]
                $Value
            )

            if ($null -eq $Value) {
                return $null
            }

            if ($Value -is [string]) {
                if ([string]::IsNullOrWhiteSpace($Value)) {
                    return $null
                }
                return $Value.ToUpperInvariant()
            }

            if ($Value -is [byte[]]) {
                return ([System.BitConverter]::ToString($Value)).Replace('-', '').ToUpperInvariant()
            }

            return $Value.ToString().ToUpperInvariant()
        }

        $convertToBoolean = {
            param(
                [Parameter(Mandatory)]
                $Value
            )

            if ($Value -is [bool]) {
                return $Value
            }

            if ($null -eq $Value) {
                return $false
            }

            if ($Value -is [string]) {
                $normalized = $Value.Trim()
                if (-not $normalized) {
                    return $false
                }

                switch -Regex ($normalized) {
                    '^(?i:true)$' { return $true }
                    '^(?i:false)$' { return $false }
                    default { throw "Boolean value '$Value' must be 'True' or 'False'." }
                }
            }

            return [bool]$Value
        }

        $environmentStatus = Initialize-PwnedPassCheckDataEnvironment
        if ($environmentStatus.DataDirectoryCreated) {
            Write-Verbose "Created data directory at '$($environmentStatus.DataDirectory)'."
        }

        if ($environmentStatus.AuditLogCreated) {
            Write-Verbose "Created default audit log at '$($environmentStatus.AuditLogPath)'."
        }

        if ($environmentStatus.SettingsFileCreated) {
            $settingsPrompt = "A new settings file was created at '$($environmentStatus.SettingsPath)'. Update the configuration before rerunning."
            Write-Warning $settingsPrompt
            if (-not $PSBoundParameters.ContainsKey('SettingsPath')) {
                throw $settingsPrompt
            }
        }

        $compromisedAccountSummaries = New-Object System.Collections.Specialized.OrderedDictionary
        $sharedPasswordGroups = @()
        $sharedPasswordTracker = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $moduleRoot = Split-Path -Parent $PSScriptRoot
        $repoRoot = Split-Path -Parent $moduleRoot

        $candidatePaths = @()
        if ($PSBoundParameters.ContainsKey('SettingsPath')) {
            $candidatePaths += $SettingsPath
        }

        $candidatePaths += @(
            $script:DefaultSettingsPath,
            (Join-Path -Path $repoRoot -ChildPath 'PwnedPassCheckSettings.psd1'),
            (Join-Path -Path $moduleRoot -ChildPath 'PwnedPassCheckSettings.psd1')
        ) | Where-Object { $_ }

        $settingsFile = $candidatePaths | Where-Object { Test-Path -Path $_ } | Select-Object -First 1
        if (-not $settingsFile) {
            throw "PwnedPassCheckSettings.psd1 was not found. Provide the SettingsPath parameter or place the file in C:\PwndPassCheck."
        }

        try {
            $settings = Import-PowerShellDataFile -Path $settingsFile
        } catch {
            throw "Failed to read settings file '$settingsFile': $_"
        }

        Write-Verbose "Loaded settings from '$settingsFile'"

        $adDomain = $settings.ADDomain
        if (-not $adDomain -or [string]::IsNullOrWhiteSpace($adDomain)) {
            throw "AD Domain must be provided in PwnedPassCheckSettings.psd1."
        }

        $domainControllerSetting = $settings.DomainControllers
        if (-not $domainControllerSetting) {
            throw "At least one domain controller must be specified in the DomainControllers setting."
        }

        if ($domainControllerSetting -is [string]) {
            $resolvedControllers = $domainControllerSetting -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        } elseif ($domainControllerSetting -is [System.Collections.IEnumerable]) {
            $resolvedControllers = @($domainControllerSetting) | ForEach-Object { $_ } | ForEach-Object { $_.ToString().Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        } else {
            throw "DomainControllers must be a comma-separated string or array of host names."
        }

        if (-not $resolvedControllers) {
            throw "DomainControllers could not be parsed from the settings file."
        }

        $resolvedControllers = $resolvedControllers | Sort-Object -Unique

        foreach ($requiredToggle in 'NotifyUser', 'NotifyManager') {
            if (-not $settings.ContainsKey($requiredToggle)) {
                throw "'$requiredToggle' must be specified in the settings file."
            }
        }

        $notifyUser = & $convertToBoolean -Value $settings.NotifyUser
        $notifyManager = & $convertToBoolean -Value $settings.NotifyManager
        $reportingFrequency = $null
        if ($settings.ReportingFrequency) {
            $reportingFrequencyValue = $settings.ReportingFrequency.ToString().Trim()
            if ($reportingFrequencyValue) {
                switch -Regex ($reportingFrequencyValue) {
                    '^(?i)weekly$' { $reportingFrequency = 'Weekly' }
                    '^(?i)monthly$' { $reportingFrequency = 'Monthly' }
                    default { throw "ReportingFrequency must be 'Weekly' or 'Monthly' when specified." }
                }
            }
        }

        if ($notifyManager -and -not $reportingFrequency) {
            throw "ReportingFrequency must be set to 'Weekly' or 'Monthly' when manager notifications are enabled."
        }

        $managersToNotify = @()
        if ($settings.ManagersToNotify) {
            if ($settings.ManagersToNotify -is [string]) {
                $managersToNotify = $settings.ManagersToNotify -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            } elseif ($settings.ManagersToNotify -is [System.Collections.IEnumerable]) {
                $managersToNotify = @($settings.ManagersToNotify) | ForEach-Object { $_ } | ForEach-Object { $_.ToString().Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            } else {
                throw "ManagersToNotify must be a comma-separated string or array of email addresses."
            }
        }

        $notificationSettings = $null
        if ($notifyUser -or $notifyManager) {
            $notificationSettingsData = [ordered]@{
                NotifyUser         = $notifyUser
                NotifyManager      = $notifyManager
                ManagersToNotify   = $managersToNotify
                ReportingFrequency = $reportingFrequency
            }

            $requiredNotificationFields = 'FromAddress', 'EmailUserAccount', 'EmailUserPassword', 'SendingPort', 'EncryptionType', 'SmtpServer'
            foreach ($field in $requiredNotificationFields) {
                if (-not $settings.ContainsKey($field) -or [string]::IsNullOrWhiteSpace($settings[$field])) {
                    throw "'$field' must be provided in the settings file when user or manager notifications are enabled."
                }
            }

            $portValue = $settings.SendingPort.ToString().Trim()
            $port = $null
            if (-not [int]::TryParse($portValue, [ref]$port)) {
                throw "SendingPort must be a valid integer when user or manager notifications are enabled."
            }

            $encryptionTypeValue = $settings.EncryptionType.ToString().Trim()
            $normalizedEncryption = $null
            switch -Regex ($encryptionTypeValue) {
                '^(?i)none$' { $normalizedEncryption = 'None' }
                '^(?i)starttls$' { $normalizedEncryption = 'StartTLS' }
                '^(?i)startls$' { $normalizedEncryption = 'StartTLS' }
                '^(?i)ssl\s*/\s*tls$' { $normalizedEncryption = 'SSL/TLS' }
                default { throw "EncryptionType must be one of: None, StartTLS, SSL/TLS." }
            }

            $smtpServer = $settings.SmtpServer.ToString().Trim()
            if (-not $smtpServer) {
                throw "SmtpServer must be specified when user or manager notifications are enabled."
            }

            try {
                $notificationCredential = New-Object System.Net.NetworkCredential($settings.EmailUserAccount, $settings.EmailUserPassword)
            } catch {
                throw "Failed to create network credential for the notification account: $_"
            }

            $notificationSettingsData.FromAddress = $settings.FromAddress
            $notificationSettingsData.EmailUserAccount = $settings.EmailUserAccount
            $notificationSettingsData.EmailUserPassword = $settings.EmailUserPassword
            $notificationSettingsData.SendingPort = [int]$port
            $notificationSettingsData.EncryptionType = $normalizedEncryption
            $notificationSettingsData.SmtpServer = $smtpServer
            $notificationSettingsData.Credential = $notificationCredential

            $notificationSettings = [pscustomobject]$notificationSettingsData
        }

        $effectiveApiRoot = $ApiRoot
        if (-not $PSBoundParameters.ContainsKey('ApiRoot') -and $settings.ContainsKey('HIBPApiRoot')) {
            $candidateApiRoot = $settings.HIBPApiRoot
            if ($candidateApiRoot) {
                $candidateApiRootString = $candidateApiRoot.ToString().Trim()
                if ($candidateApiRootString) {
                    $effectiveApiRoot = $candidateApiRootString
                }
            }
        }

        $effectiveApiKey = $null
        if ($PSBoundParameters.ContainsKey('ApiKey')) {
            $candidateApiKey = $ApiKey
            if ($candidateApiKey -and -not [string]::IsNullOrWhiteSpace($candidateApiKey)) {
                $effectiveApiKey = $candidateApiKey.Trim()
            }
        } elseif ($settings.ContainsKey('HIBPApiKey')) {
            $candidateApiKey = $settings.HIBPApiKey
            if ($candidateApiKey) {
                $candidateApiKeyString = $candidateApiKey.ToString().Trim()
                if ($candidateApiKeyString) {
                    $effectiveApiKey = $candidateApiKeyString
                }
            }
        }

        if ($effectiveApiKey) {
            Test-ValidHibpApiKey -ApiKey $effectiveApiKey -ThrowOnFail
        }

        $effectiveUserAgent = $null
        if ($PSBoundParameters.ContainsKey('UserAgent')) {
            $candidateUserAgent = $UserAgent
            if ($candidateUserAgent -and -not [string]::IsNullOrWhiteSpace($candidateUserAgent)) {
                $effectiveUserAgent = $candidateUserAgent
            }
        } elseif ($settings.ContainsKey('HIBPUserAgent')) {
            $candidateUserAgent = $settings.HIBPUserAgent
            if ($candidateUserAgent) {
                $candidateUserAgentString = $candidateUserAgent.ToString().Trim()
                if ($candidateUserAgentString) {
                    $effectiveUserAgent = $candidateUserAgentString
                }
            }
        }

        if ($PSBoundParameters.ContainsKey('RequestPadding')) {
            $effectiveRequestPadding = [bool]$RequestPadding
        } elseif ($settings.ContainsKey('HIBPRequestPadding')) {
            $effectiveRequestPadding = & $convertToBoolean -Value $settings.HIBPRequestPadding
        } else {
            $effectiveRequestPadding = $false
        }

        if ($PSBoundParameters.ContainsKey('NoModeQueryString')) {
            $effectiveNoModeQueryString = [bool]$NoModeQueryString
        } elseif ($settings.ContainsKey('HIBPNoModeQueryString')) {
            $effectiveNoModeQueryString = & $convertToBoolean -Value $settings.HIBPNoModeQueryString
        } else {
            $effectiveNoModeQueryString = $false
        }

        $hashQueryParams = @{ ApiRoot = $effectiveApiRoot }
        if ($effectiveApiKey) { $hashQueryParams.ApiKey = $effectiveApiKey }
        if ($effectiveUserAgent) { $hashQueryParams.UserAgent = $effectiveUserAgent }
        if ($effectiveRequestPadding) { $hashQueryParams.RequestPadding = $true }
        if ($effectiveNoModeQueryString) { $hashQueryParams.NoModeQueryString = $true }

        if ($effectiveApiRoot -and $effectiveApiRoot -like 'http*') {
            Write-Verbose "Performing Have I Been Pwned API preflight check..."
            try {
                $preflightHash = '0000000000000000000000000000000000000000'
                Get-PwnedHash -PasswordHash $preflightHash @hashQueryParams | Out-Null
                Write-Verbose "Have I Been Pwned API preflight check succeeded."
            } catch {
                $errorRecord = $_
                $statusCode = $null
                $exception = $errorRecord.Exception

                if ($exception) {
                    if ($exception.PSObject.Properties['Response']) {
                        $response = $exception.Response
                        if ($response -and $response.PSObject.Properties['StatusCode']) {
                            $statusCode = [int]$response.StatusCode
                        }
                    }

                    if (-not $statusCode -and $exception.PSObject.Properties['StatusCode']) {
                        $statusCode = [int]$exception.StatusCode
                    }

                    if (-not $statusCode -and $exception.InnerException -and $exception.InnerException.PSObject.Properties['Response']) {
                        $innerResponse = $exception.InnerException.Response
                        if ($innerResponse -and $innerResponse.PSObject.Properties['StatusCode']) {
                            $statusCode = [int]$innerResponse.StatusCode
                        }
                    }
                }

                if ($statusCode -eq 401) {
                    throw "Preflight call to the Have I Been Pwned API returned 401 Unauthorized. Verify the hibp-api-key value and subscription status before running the audit."
                }

                $failureMessage = $errorRecord.ToString()
                if ($exception -and $exception.Message) {
                    $failureMessage = $exception.Message
                }

                throw "Preflight call to the Have I Been Pwned API failed: $failureMessage"
            }
        }

        $seenAccountIds = @{}
        $hashCache = @{}

        $minimumUserNotificationInterval = [System.TimeSpan]::FromDays(1)

        $auditLogCandidates = @()
        if ($PSBoundParameters.ContainsKey('AuditLogPath')) {
            $auditLogCandidates += $AuditLogPath
        }

        $defaultAuditLogPaths = @(
            $script:DefaultAuditLogPath,
            (Join-Path -Path $repoRoot -ChildPath 'PwnedPassCheckAuditLog.json'),
            (Join-Path -Path $moduleRoot -ChildPath 'PwnedPassCheckAuditLog.json')
        ) | Where-Object { $_ }

        $auditLogCandidates += $defaultAuditLogPaths

        if ($PSBoundParameters.ContainsKey('AuditLogPath')) {
            $resolvedAuditLogPath = $AuditLogPath
        } else {
            $resolvedAuditLogPath = $auditLogCandidates | Where-Object { Test-Path -Path $_ } | Select-Object -First 1
            if (-not $resolvedAuditLogPath) {
                $resolvedAuditLogPath = $defaultAuditLogPaths | Select-Object -First 1
            }
        }

        if (-not $resolvedAuditLogPath) {
            throw "Unable to determine an audit log path. Provide the AuditLogPath parameter or use C:\PwndPassCheck\PwnedPassCheckAuditLog.json."
        }

        try {
            $auditLogState = Import-PwnedAuditLog -Path $resolvedAuditLogPath
        } catch {
            throw "Failed to load audit log from '$resolvedAuditLogPath': $_"
        }

        $auditLogEntries = $auditLogState.Entries
        $auditLogMetadata = $auditLogState.Metadata
        if (-not $auditLogMetadata) {
            $auditLogMetadata = New-Object System.Collections.Specialized.OrderedDictionary
        }
        $auditLogUpdated = $false

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

        $managerSummaryLastSentOn = $null
        if ($auditLogMetadata.Contains('ManagerSummaryLastSentOn')) {
            $managerSummaryLastSentOn = & $parseDateTime -Value $auditLogMetadata['ManagerSummaryLastSentOn']
        }

        Write-Verbose "Processing domain '$adDomain' using controllers: $($resolvedControllers -join ', ')"
        if ($notificationSettings) {
            Write-Verbose "Notification settings loaded for user notifications: $($notificationSettings.NotifyUser); manager notifications: $($notificationSettings.NotifyManager)"
        }

        $managerNotificationCandidates = New-Object System.Collections.ArrayList
    }

    process {
        foreach ($controller in $resolvedControllers) {
            $accounts = & $getDomainAccounts -DomainController $controller
            if (-not $accounts) {
                Write-Warning "No accounts returned from domain controller '$controller'."
                continue
            }

            foreach ($account in $accounts) {
                if (-not $account.Guid) {
                    # Use DistinguishedName when Guid is unavailable to avoid duplicates.
                    $accountId = $account.DistinguishedName
                } else {
                    $accountId = $account.Guid.ToString()
                }

                if ($seenAccountIds.ContainsKey($accountId)) {
                    continue
                }
                $seenAccountIds[$accountId] = $true

                $hashString = & $convertNTHashToString -Value $account.NTHash
                if (-not $hashString) {
                    continue
                }

                if ($hashCache.ContainsKey($hashString)) {
                    $seenCount = $hashCache[$hashString]
                } else {
                    try {
                        $result = Get-PwnedHash -PasswordHash $hashString @hashQueryParams
                        $seenCount = $result.SeenCount
                        $hashCache[$hashString] = $seenCount
                    } catch {
                        Write-Warning "Failed to query Have I Been Pwned for $($account.SamAccountName): $_"
                        continue
                    }
                }

                $now = (Get-Date).ToUniversalTime()
                $accountPasswordLastSet = $null
                if ($account.PasswordLastSet) {
                    $accountPasswordLastSet = ([datetime]$account.PasswordLastSet).ToUniversalTime()
                }

                $existingEntry = $null
                if ($auditLogEntries.Contains($accountId)) {
                    $existingEntry = $auditLogEntries[$accountId]
                }

                $existingUserNotified = $false
                $existingUserNotifiedOn = $null
                $existingManagerNotified = $false
                $existingManagerNotifiedOn = $null
                $existingPasswordLastSet = $null
                $existingPasswordChangedAfterNotification = $false
                $existingPasswordChangedOn = $null
                $existingUserNotificationCount = 0

                if ($existingEntry) {
                    if ($existingEntry.UserNotified -is [bool]) {
                        $existingUserNotified = $existingEntry.UserNotified
                    } elseif ($null -ne $existingEntry.UserNotified) {
                        $existingUserNotified = [bool]$existingEntry.UserNotified
                    }

                    $existingUserNotifiedOn = & $parseDateTime -Value $existingEntry.UserNotifiedOn

                    if ($existingEntry.ManagerNotified -is [bool]) {
                        $existingManagerNotified = $existingEntry.ManagerNotified
                    } elseif ($null -ne $existingEntry.ManagerNotified) {
                        $existingManagerNotified = [bool]$existingEntry.ManagerNotified
                    }

                    $existingManagerNotifiedOn = & $parseDateTime -Value $existingEntry.ManagerNotifiedOn
                    $existingPasswordLastSet = & $parseDateTime -Value $existingEntry.PasswordLastSet

                    if ($existingEntry.PasswordChangedAfterNotification -is [bool]) {
                        $existingPasswordChangedAfterNotification = $existingEntry.PasswordChangedAfterNotification
                    } elseif ($null -ne $existingEntry.PasswordChangedAfterNotification) {
                        $existingPasswordChangedAfterNotification = [bool]$existingEntry.PasswordChangedAfterNotification
                    }

                    $existingPasswordChangedOn = & $parseDateTime -Value $existingEntry.PasswordChangedOn

                    if ($existingEntry -is [System.Collections.IDictionary]) {
                        if ($existingEntry.Contains('UserNotificationCount')) {
                            $notificationCountValue = $existingEntry['UserNotificationCount']
                            if ($notificationCountValue -is [int]) {
                                $existingUserNotificationCount = $notificationCountValue
                            } elseif ($null -ne $notificationCountValue) {
                                $parsedCount = 0
                                if ([int]::TryParse($notificationCountValue.ToString(), [ref]$parsedCount)) {
                                    $existingUserNotificationCount = $parsedCount
                                }
                            }
                        }
                    } elseif ($existingEntry.PSObject.Properties['UserNotificationCount']) {
                        $notificationCountValue = $existingEntry.PSObject.Properties['UserNotificationCount'].Value
                        if ($notificationCountValue -is [int]) {
                            $existingUserNotificationCount = $notificationCountValue
                        } elseif ($null -ne $notificationCountValue) {
                            $parsedCount = 0
                            if ([int]::TryParse($notificationCountValue.ToString(), [ref]$parsedCount)) {
                                $existingUserNotificationCount = $parsedCount
                            }
                        }
                    }
                }

                if ($existingUserNotificationCount -lt 0) {
                    $existingUserNotificationCount = 0
                }

                $passwordChangedAfterNotification = $existingPasswordChangedAfterNotification
                $passwordChangedOn = $existingPasswordChangedOn

                $userNotified = [bool]$existingUserNotified
                $userNotifiedOn = $existingUserNotifiedOn
                $userNotificationCount = [int]$existingUserNotificationCount

                if ($accountPasswordLastSet -and $existingPasswordLastSet -and $accountPasswordLastSet -gt $existingPasswordLastSet) {
                    if ($existingUserNotified -or $existingManagerNotified) {
                        $passwordChangedAfterNotification = $true
                        $passwordChangedOn = $accountPasswordLastSet
                    } else {
                        $passwordChangedAfterNotification = $false
                        $passwordChangedOn = $null
                    }
                }

                if ($notificationSettings -and $notificationSettings.NotifyUser -and ($seenCount -gt 0)) {
                    $userEmailAddress = $null
                    if ($account.Mail -and -not [string]::IsNullOrWhiteSpace($account.Mail.ToString())) {
                        $userEmailAddress = $account.Mail.ToString().Trim()
                    } elseif ($account.UserPrincipalName -and -not [string]::IsNullOrWhiteSpace($account.UserPrincipalName.ToString()) -and $account.UserPrincipalName.ToString().Contains('@')) {
                        $userEmailAddress = $account.UserPrincipalName.ToString().Trim()
                    } elseif ($account.EmailAddress -and -not [string]::IsNullOrWhiteSpace($account.EmailAddress.ToString())) {
                        $userEmailAddress = $account.EmailAddress.ToString().Trim()
                    }

                    if ($userEmailAddress) {
                        $shouldSendNotification = $true
                        if ($userNotifiedOn) {
                            $timeSinceLastNotification = $now - $userNotifiedOn
                            if ($timeSinceLastNotification -lt $minimumUserNotificationInterval) {
                                $shouldSendNotification = $false
                                Write-Verbose "Skipping notification for $($account.SamAccountName); last notification sent on $($userNotifiedOn.ToString('u'))."
                            }
                        }

                        if ($shouldSendNotification) {
                            $nextNotificationCount = $userNotificationCount + 1
                            $recipientDisplayName = $account.DisplayName
                            if (-not $recipientDisplayName) { $recipientDisplayName = $account.Name }
                            if (-not $recipientDisplayName) { $recipientDisplayName = $account.SamAccountName }

                            try {
                                Send-PwnedUserNotification -SmtpServer $notificationSettings.SmtpServer -Port $notificationSettings.SendingPort -EncryptionType $notificationSettings.EncryptionType -FromAddress $notificationSettings.FromAddress -ToAddress $userEmailAddress -RecipientDisplayName $recipientDisplayName -SamAccountName $account.SamAccountName -DetectionTimeUtc $now -SeenCount ([int]$seenCount) -NotificationCount $nextNotificationCount -Credential $notificationSettings.Credential
                                $userNotificationCount = $nextNotificationCount
                                $userNotified = $true
                                $userNotifiedOn = $now
                                $auditLogUpdated = $true
                                Write-Verbose "Sent notification email to $userEmailAddress for $($account.SamAccountName)."
                            } catch {
                                Write-Warning "Failed to send notification email to '$userEmailAddress' for $($account.SamAccountName): $_"
                            }
                        }
                    } else {
                        Write-Warning "Unable to send notification for $($account.SamAccountName); no email address was found in Active Directory."
                    }
                }

                $existingUserNotified = $userNotified
                $existingUserNotifiedOn = $userNotifiedOn

                $entryToPersist = [ordered]@{
                    AccountId                        = $accountId
                    SamAccountName                   = $account.SamAccountName
                    DistinguishedName                = $account.DistinguishedName
                    Domain                           = $adDomain
                    LastAudit                        = $now.ToString('o')
                    SeenCount                        = [int]$seenCount
                    IsPwned                          = [bool]($seenCount -gt 0)
                    UserNotified                     = [bool]$userNotified
                    UserNotifiedOn                   = if ($userNotifiedOn) { $userNotifiedOn.ToString('o') } else { $null }
                    UserNotificationCount            = [int]$userNotificationCount
                    ManagerNotified                  = [bool]$existingManagerNotified
                    ManagerNotifiedOn                = if ($existingManagerNotifiedOn) { $existingManagerNotifiedOn.ToString('o') } else { $null }
                    PasswordLastSet                  = if ($accountPasswordLastSet) { $accountPasswordLastSet.ToString('o') } else { $null }
                    PasswordChangedAfterNotification = [bool]$passwordChangedAfterNotification
                    PasswordChangedOn                = if ($passwordChangedOn) { $passwordChangedOn.ToString('o') } else { $null }
                }

                $auditLogEntries[$accountId] = $entryToPersist
                $auditLogUpdated = $true

                $summaryDisplayName = $account.DisplayName
                if (-not $summaryDisplayName) { $summaryDisplayName = $account.Name }
                if (-not $summaryDisplayName) { $summaryDisplayName = $account.SamAccountName }

                    if ($seenCount -gt 0) {
                        $compromisedSummary = [pscustomobject]@{
                            AccountId      = $accountId
                            DisplayName    = $summaryDisplayName
                            SamAccountName = $account.SamAccountName
                            Domain         = $adDomain
                            SeenCount      = [int]$seenCount
                        }

                        if ($hashString -and -not [string]::IsNullOrWhiteSpace($hashString)) {
                            $trimmedHash = $hashString.Trim()
                            if ($trimmedHash) {
                                if (-not $sharedPasswordTracker.ContainsKey($trimmedHash)) {
                                    $sharedPasswordTracker[$trimmedHash] = [System.Collections.Generic.List[object]]::new()
                                }

                                $null = $sharedPasswordTracker[$trimmedHash].Add($compromisedSummary)
                            }
                        }

                        if ($compromisedAccountSummaries.Contains($accountId)) {
                            $compromisedAccountSummaries[$accountId] = $compromisedSummary
                    } else {
                        $compromisedAccountSummaries.Add($accountId, $compromisedSummary)
                    }

                }

                if ($notificationSettings -and $notificationSettings.NotifyManager -and ($seenCount -gt 0)) {
                    $managerCandidate = [pscustomobject]@{
                        AccountId                        = $accountId
                        DisplayName                      = $summaryDisplayName
                        SamAccountName                   = $account.SamAccountName
                        Domain                           = $adDomain
                        UserNotifiedOn                   = $userNotifiedOn
                        PasswordChangedAfterNotification = [bool]$passwordChangedAfterNotification
                        PasswordChangedOn                = $passwordChangedOn
                        ManagerNotifiedOn                = $existingManagerNotifiedOn
                        SeenCount                        = [int]$seenCount
                    }

                    [void]$managerNotificationCandidates.Add($managerCandidate)
                }

                [pscustomobject]@{
                    AccountId         = $accountId
                    SamAccountName    = $account.SamAccountName
                    DistinguishedName = $account.DistinguishedName
                    Guid              = $account.Guid
                    Domain            = $adDomain
                    DomainController  = $controller
                    PasswordLastSet   = $account.PasswordLastSet
                    SeenCount         = $seenCount
                    IsPwned           = [bool]($seenCount -gt 0)
                    LastAudit         = $now
                    UserNotified      = [bool]$userNotified
                    UserNotifiedOn    = $userNotifiedOn
                    UserNotificationCount = [int]$userNotificationCount
                    ManagerNotified   = [bool]$existingManagerNotified
                    ManagerNotifiedOn = $existingManagerNotifiedOn
                    PasswordChangedAfterNotification = [bool]$passwordChangedAfterNotification
                    PasswordChangedOn = $passwordChangedOn
                }
            }
        }
    }

    end {
        $accountGroupMap = @{}
        $sharedPasswordGroups = @()

        if ($sharedPasswordTracker -and ($sharedPasswordTracker.Count -gt 0)) {
            $groupEntries = $sharedPasswordTracker.GetEnumerator() |
                Where-Object { $_.Value.Count -gt 1 } |
                Sort-Object -Property @{ Expression = { $_.Value.Count }; Descending = $true }, @{ Expression = { $_.Key } }

            $groupIndex = 1
            foreach ($groupEntry in $groupEntries) {
                $accountsInGroup = @($groupEntry.Value)
                if (-not $accountsInGroup) { continue }

                $groupId = "Shared Password Group $groupIndex"
                $groupIndex++

                foreach ($accountSummary in $accountsInGroup) {
                    if (-not $accountSummary) { continue }

                    if ($accountSummary.PSObject.Properties['SharedPasswordGroupId']) {
                        $accountSummary.PSObject.Properties['SharedPasswordGroupId'].Value = $groupId
                    } else {
                        $accountSummary | Add-Member -NotePropertyName 'SharedPasswordGroupId' -NotePropertyValue $groupId
                    }

                    if ($accountSummary.PSObject.Properties['AccountId'] -and $accountSummary.AccountId) {
                        $accountGroupMap[$accountSummary.AccountId] = $groupId
                    }
                }

                $sharedPasswordGroups += [pscustomobject]@{
                    GroupId  = $groupId
                    Accounts = $accountsInGroup
                }
            }
        }

        if ($compromisedAccountSummaries) {
            foreach ($summary in $compromisedAccountSummaries.Values) {
                if ($summary.PSObject.Properties['SharedPasswordGroupId']) {
                    if (-not $summary.SharedPasswordGroupId) {
                        $summary.SharedPasswordGroupId = $null
                    }
                } else {
                    $summary | Add-Member -NotePropertyName 'SharedPasswordGroupId' -NotePropertyValue $null
                }
            }
        }

        if ($managerNotificationCandidates) {
            foreach ($candidate in $managerNotificationCandidates) {
                $groupId = $null
                if ($candidate.AccountId -and $accountGroupMap.ContainsKey($candidate.AccountId)) {
                    $groupId = $accountGroupMap[$candidate.AccountId]
                }

                if ($candidate.PSObject.Properties['SharedPasswordGroupId']) {
                    $candidate.SharedPasswordGroupId = $groupId
                } else {
                    $candidate | Add-Member -NotePropertyName 'SharedPasswordGroupId' -NotePropertyValue $groupId
                }
            }
        }

        if ($notificationSettings -and $notificationSettings.NotifyManager) {
            $managerRecipients = @()
            if ($notificationSettings.ManagersToNotify) {
                $managerRecipients = @($notificationSettings.ManagersToNotify | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) }) | Sort-Object -Unique
            }

            $managerSummaryRecords = @()
            if ($managerNotificationCandidates) {
                $managerSummaryRecords = @($managerNotificationCandidates | Sort-Object DisplayName, SamAccountName)
            }

            if (-not $managerRecipients) {
                Write-Warning 'Manager notifications are enabled, but no manager email addresses were provided in ManagersToNotify.'
            } elseif (-not $managerSummaryRecords) {
                Write-Verbose 'No compromised accounts require manager notification at this time.'
            } else {
                $nowUtc = (Get-Date).ToUniversalTime()
                $minimumInterval = switch ($notificationSettings.ReportingFrequency) {
                    'Weekly'  { [System.TimeSpan]::FromDays(7) }
                    'Monthly' { [System.TimeSpan]::FromDays(30) }
                }

                $shouldSendManagerNotification = $false
                if (-not $managerSummaryLastSentOn) {
                    $shouldSendManagerNotification = $true
                } else {
                    $timeSinceLastSummary = $nowUtc - $managerSummaryLastSentOn
                    if ($timeSinceLastSummary -ge $minimumInterval) {
                        $shouldSendManagerNotification = $true
                    } else {
                        Write-Verbose "Skipping manager notification; last summary sent on $($managerSummaryLastSentOn.ToString('u'))."
                    }
                }

                if ($shouldSendManagerNotification) {
                    try {
                        Send-PwnedManagerNotification -SmtpServer $notificationSettings.SmtpServer -Port $notificationSettings.SendingPort -EncryptionType $notificationSettings.EncryptionType -FromAddress $notificationSettings.FromAddress -ToAddresses $managerRecipients -SummaryRecords $managerSummaryRecords -ReportingFrequency $notificationSettings.ReportingFrequency -Credential $notificationSettings.Credential
                        Write-Verbose "Sent manager notification summary to $($managerRecipients -join ', ')."

                        $timestampString = $nowUtc.ToString('o')
                        if ($auditLogMetadata.Contains('ManagerSummaryLastSentOn')) {
                            $auditLogMetadata['ManagerSummaryLastSentOn'] = $timestampString
                        } else {
                            $auditLogMetadata.Add('ManagerSummaryLastSentOn', $timestampString)
                        }

                        foreach ($record in $managerSummaryRecords) {
                            if ($auditLogEntries.Contains($record.AccountId)) {
                                $entry = $auditLogEntries[$record.AccountId]
                                if ($entry -is [System.Collections.IDictionary]) {
                                    $entry['ManagerNotified'] = $true
                                    $entry['ManagerNotifiedOn'] = $timestampString
                                } elseif ($entry.PSObject.Properties['ManagerNotified']) {
                                    $entry.ManagerNotified = $true
                                    $entry.ManagerNotifiedOn = $timestampString
                                }
                                $auditLogEntries[$record.AccountId] = $entry
                            }
                        }

                        $auditLogUpdated = $true
                        $managerSummaryLastSentOn = $nowUtc
                    } catch {
                        Write-Warning "Failed to send manager notification summary: $_"
                    }
                }
            }
        }

        if ($auditLogUpdated) {
            try {
                Export-PwnedAuditLog -Path $resolvedAuditLogPath -Entries $auditLogEntries -Metadata $auditLogMetadata | Out-Null
            } catch {
                throw "Failed to persist audit log to '$resolvedAuditLogPath': $_"
            }
        }

        $compromisedAccounts = @()
        if ($compromisedAccountSummaries) {
            $compromisedAccounts = @($compromisedAccountSummaries.Values)
        }

        $totalCompromisedCount = $compromisedAccounts.Count
        $totalSharedAccountCount = 0
        foreach ($group in $sharedPasswordGroups) {
            $totalSharedAccountCount += $group.Accounts.Count
        }

        $formatAccountForDisplay = {
            param(
                [Parameter(Mandatory)]
                $Account
            )

            $label = $null
            if ($Account.DisplayName -and $Account.SamAccountName -and ($Account.DisplayName -ne $Account.SamAccountName)) {
                $label = "$($Account.DisplayName) [$($Account.SamAccountName)]"
            } elseif ($Account.DisplayName) {
                $label = $Account.DisplayName
            } elseif ($Account.SamAccountName) {
                $label = $Account.SamAccountName
            } else {
                $label = 'Unknown Account'
            }

            return $label
        }

        Write-Host ''
        Write-Host 'Unsafe Password Summary' -ForegroundColor Cyan
        Write-Host ('=' * 80)
        Write-Host ''

        $summaryMetrics = @(
            [pscustomobject]@{ Metric = 'Total unsafe accounts'; Value = $totalCompromisedCount }
            [pscustomobject]@{ Metric = 'Total accounts sharing passwords'; Value = $totalSharedAccountCount }
        )

        foreach ($metric in $summaryMetrics) {
            $label = $metric.Metric.PadRight(40)
            Write-Host ("$label : {0}" -f $metric.Value)
        }

        Write-Host ''
        if ($totalCompromisedCount -gt 0) {
            Write-Host 'Compromised Accounts' -ForegroundColor Yellow
            Write-Host ('-' * 80)
            foreach ($account in ($compromisedAccounts | Sort-Object DisplayName, SamAccountName)) {
                $label = & $formatAccountForDisplay $account
                $seenCountSuffix = ''
                if ($null -ne $account.SeenCount -and ($account.SeenCount -gt 0)) {
                    $seenCountSuffix = " - Seen $($account.SeenCount) time(s)"
                }

                Write-Host " - $label$seenCountSuffix"
            }
        } else {
            Write-Host 'Compromised Accounts' -ForegroundColor Yellow
            Write-Host ('-' * 80)
            Write-Host ' - None detected.'
        }

        Write-Host ''
        Write-Host 'Shared Password Groups' -ForegroundColor Yellow
        Write-Host ('-' * 80)
        if ($sharedPasswordGroups) {
            foreach ($group in $sharedPasswordGroups) {
                Write-Host ("{0} (Accounts: {1})" -f $group.GroupId, $group.Accounts.Count) -ForegroundColor Magenta
                foreach ($account in ($group.Accounts | Sort-Object DisplayName, SamAccountName)) {
                    $label = & $formatAccountForDisplay $account
                    $seenCountSuffix = ''
                    if ($null -ne $account.SeenCount -and ($account.SeenCount -gt 0)) {
                        $seenCountSuffix = " - Seen $($account.SeenCount) time(s)"
                    }

                    Write-Host "   - $label$seenCountSuffix"
                }
                Write-Host ''
            }
        } else {
            Write-Host ' - None detected.'
            Write-Host ''
        }
    }
}
