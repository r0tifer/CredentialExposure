function Send-PwnedManagerNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SmtpServer,
        [Parameter(Mandatory)]
        [int]$Port,
        [Parameter(Mandatory)]
        [ValidateSet('None', 'StartTLS', 'SSL/TLS')]
        [string]$EncryptionType,
        [Parameter(Mandatory)]
        [string]$FromAddress,
        [Parameter(Mandatory)]
        [string[]]$ToAddresses,
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$SummaryRecords,
        [System.Collections.IEnumerable]$SharedPasswordGroups,
        [Parameter(Mandatory)]
        [ValidateSet('Weekly', 'Monthly')]
        [string]$ReportingFrequency,
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $recipients = @($ToAddresses | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) }) | Sort-Object -Unique
    if (-not $recipients) {
        return
    }

    $records = @($SummaryRecords)
    if (-not $records) {
        return
    }

    $encodeValue = {
        param($Value)

        if ($null -eq $Value) {
            return ''
        }

        return [System.Net.WebUtility]::HtmlEncode($Value.ToString())
    }

    $recordCount = $records.Count
    $subject = "Unsafe Password Summary - $ReportingFrequency Report"

    if ($recordCount -eq 1) {
        $executiveSummary = 'One user account currently has an unsafe password that requires follow-up.'
    } else {
        $executiveSummary = "$recordCount user accounts currently have unsafe passwords that require follow-up."
    }

    $sortedRecords = @($records | Sort-Object DisplayName, SamAccountName)

    $sharedPasswordGroupsInput = @()
    if ($PSBoundParameters.ContainsKey('SharedPasswordGroups') -and $SharedPasswordGroups) {
        $sharedPasswordGroupsInput = @($SharedPasswordGroups | Where-Object { $_ })
    }

    $sharedPasswordGroups = @()
    $sharedAccountCount = 0
    if ($sharedPasswordGroupsInput) {
        $sharedPasswordGroups = @(
            $sharedPasswordGroupsInput |
                Where-Object {
                    $_ -and $_.PSObject.Properties['Accounts'] -and (@($_.Accounts).Count -gt 1)
                } |
                ForEach-Object {
                    $accounts = @($_.Accounts)
                    [pscustomobject]@{
                        GroupId  = if ($_.PSObject.Properties['GroupId'] -and $_.GroupId) { $_.GroupId } else { 'Shared Password Group' }
                        Accounts = $accounts
                    }
                } |
                Where-Object { $_.Accounts } |
                Sort-Object -Property @{ Expression = { $_.Accounts.Count }; Descending = $true }, @{ Expression = { $_.GroupId } }
        )

        foreach ($group in $sharedPasswordGroups) {
            $sharedAccountCount += $group.Accounts.Count
        }
    } elseif ($sortedRecords) {
        $sharedPasswordGroups = @(
            $sortedRecords |
                Where-Object { $_.SharedPasswordGroupId } |
                Group-Object -Property SharedPasswordGroupId |
                Where-Object { $_.Count -gt 1 } |
                ForEach-Object {
                    $groupId = if ($_.Name) { $_.Name } else { 'Shared Password Group' }
                    $accounts = @($_.Group)
                    [pscustomobject]@{
                        GroupId  = $groupId
                        Accounts = $accounts
                    }
                } |
                Sort-Object -Property @{ Expression = { $_.Accounts.Count }; Descending = $true }, @{ Expression = { $_.GroupId } }
        )

        foreach ($group in $sharedPasswordGroups) {
            $sharedAccountCount += $group.Accounts.Count
        }
    }

    $sharedAccountsSentence = $null
    if ($sharedAccountCount -gt 0) {
        $sharedAccountWord = if ($sharedAccountCount -eq 1) { 'account' } else { 'accounts' }
        $sharedAccountsSentence = "$sharedAccountCount of these $sharedAccountWord share the same password with another active user, increasing the risk of compromise spreading between accounts."
    } else {
        $sharedAccountsSentence = 'No accounts are currently sharing the same password, but every password listed below has appeared in a known data breach.'
    }

    $executiveSummaryDetails = "{0} {1} Review the tables below to see who has been notified and whether a password change has been completed." -f $executiveSummary.Trim(), $sharedAccountsSentence

    $recordDisplayCache = @{}
    $buildUserCell = {
        param($Record)

        $displayName = $Record.DisplayName
        $samAccountName = $Record.SamAccountName
        $domain = $Record.Domain

        $userLines = @()
        if ($displayName -and $samAccountName -and ($displayName -ne $samAccountName)) {
            $userLines += (& $encodeValue $displayName)
            $userLines += "<span class=`"muted`">$(& $encodeValue $samAccountName)</span>"
        } elseif ($displayName) {
            $userLines += (& $encodeValue $displayName)
        } elseif ($samAccountName) {
            $userLines += (& $encodeValue $samAccountName)
        } else {
            $userLines += 'Unknown Account'
        }

        if ($domain) {
            $userLines += "<span class=`"muted`">Domain: $(& $encodeValue $domain)</span>"
        }

        return $userLines -join '<br />'
    }

    foreach ($record in $sortedRecords) {
        if ($record.AccountId -and -not $recordDisplayCache.ContainsKey($record.AccountId)) {
            $recordDisplayCache[$record.AccountId] = & $buildUserCell $record
        }
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('<!DOCTYPE html>')
    [void]$builder.AppendLine('<html lang="en">')
    [void]$builder.AppendLine('<head>')
    [void]$builder.AppendLine('<meta charset="utf-8" />')
    [void]$builder.AppendLine('<title>Unsafe Password Summary</title>')
    [void]$builder.AppendLine('<style>body { font-family: Segoe UI, Arial, Helvetica, sans-serif; font-size: 14px; color: #1a1a1a; }')
    [void]$builder.AppendLine('table { border-collapse: collapse; width: 100%; margin-top: 12px; }')
    [void]$builder.AppendLine('th, td { padding: 8px 10px; border-bottom: 1px solid #dddddd; text-align: left; }')
    [void]$builder.AppendLine('th { background-color: #f2f2f2; font-weight: 600; }')
    [void]$builder.AppendLine('.muted { color: #555555; font-size: 12px; }')
    [void]$builder.AppendLine('</style>')
    [void]$builder.AppendLine('</head>')
    [void]$builder.AppendLine('<body>')
    [void]$builder.AppendLine('<h1>Executive Summary</h1>')
    [void]$builder.AppendLine("<p>$([System.Net.WebUtility]::HtmlEncode($executiveSummaryDetails))</p>")

    [void]$builder.AppendLine('<h2>Summary</h2>')
    [void]$builder.AppendLine('<ul>')
    [void]$builder.AppendLine("<li><strong>Total accounts with unsafe passwords:</strong> $recordCount</li>")
    [void]$builder.AppendLine("<li><strong>Total accounts sharing passwords:</strong> $sharedAccountCount</li>")
    [void]$builder.AppendLine('</ul>')

    [void]$builder.AppendLine('<h2>Unsafe Accounts</h2>')
    if ($sortedRecords) {
        [void]$builder.AppendLine('<table role="presentation">')
        [void]$builder.AppendLine('<thead><tr><th scope="col">User Account</th><th scope="col">Last User Notification</th><th scope="col">Password Changed?</th></tr></thead>')
        [void]$builder.AppendLine('<tbody>')

        foreach ($record in $sortedRecords) {
            $accountId = $record.AccountId
            $userCell = $null
            if ($accountId -and $recordDisplayCache.ContainsKey($accountId)) {
                $userCell = $recordDisplayCache[$accountId]
            } else {
                $userCell = & $buildUserCell $record
            }

            $userNotificationText = 'No notification sent'
            if ($record.UserNotifiedOn) {
                try {
                    $localUserNotified = ([datetime]$record.UserNotifiedOn).ToLocalTime()
                    $userNotificationText = $localUserNotified.ToString('f')
                } catch {
                    $userNotificationText = $record.UserNotifiedOn.ToString()
                }
            }

            $passwordChangedText = 'No'
            if ($record.PasswordChangedAfterNotification) {
                $passwordChangedText = 'Yes'
                if ($record.PasswordChangedOn) {
                    try {
                        $localPasswordChanged = ([datetime]$record.PasswordChangedOn).ToLocalTime()
                        $passwordChangedText = "Yes (on $($localPasswordChanged.ToString('f')))"
                    } catch {
                        $passwordChangedText = "Yes (on $($record.PasswordChangedOn.ToString()))"
                    }
                }
            }

            [void]$builder.AppendLine('<tr>')
            [void]$builder.AppendLine("<td>$userCell</td>")
            [void]$builder.AppendLine("<td>$([System.Net.WebUtility]::HtmlEncode($userNotificationText))</td>")
            [void]$builder.AppendLine("<td>$([System.Net.WebUtility]::HtmlEncode($passwordChangedText))</td>")
            [void]$builder.AppendLine('</tr>')
        }

        [void]$builder.AppendLine('</tbody>')
        [void]$builder.AppendLine('</table>')
    } else {
        [void]$builder.AppendLine('<p>No unsafe accounts detected.</p>')
    }

    [void]$builder.AppendLine('<h2>Shared Password Groups</h2>')
    if ($sharedPasswordGroups) {
        foreach ($group in $sharedPasswordGroups) {
            $groupLabel = $group.GroupId
            if (-not $groupLabel) {
                $groupLabel = 'Shared Password Group'
            }

            $groupAccounts = @($group.Accounts)
            if (-not $groupAccounts) {
                continue
            }

            $groupLabel = & $encodeValue $groupLabel
            [void]$builder.AppendLine("<h3>$groupLabel</h3>")
            [void]$builder.AppendLine('<ul>')

            foreach ($record in ($groupAccounts | Sort-Object DisplayName, SamAccountName)) {
                $accountId = $record.AccountId
                $userCell = $null
                if ($accountId -and $recordDisplayCache.ContainsKey($accountId)) {
                    $userCell = $recordDisplayCache[$accountId]
                } else {
                    $userCell = & $buildUserCell $record
                }

                [void]$builder.AppendLine("<li>$userCell</li>")
            }

            [void]$builder.AppendLine('</ul>')
        }
    } else {
        [void]$builder.AppendLine('<p>No accounts are currently sharing passwords.</p>')
    }
    [void]$builder.AppendLine('<p class="muted">This message was generated automatically. If you have questions, contact the security team.</p>')
    [void]$builder.AppendLine('</body>')
    [void]$builder.AppendLine('</html>')

    $body = $builder.ToString()

    $mailMessage = New-Object System.Net.Mail.MailMessage
    try {
        $mailMessage.From = New-Object System.Net.Mail.MailAddress($FromAddress)
        foreach ($recipient in $recipients) {
            $mailMessage.To.Add((New-Object System.Net.Mail.MailAddress($recipient)))
        }

        $mailMessage.Subject = $subject
        $mailMessage.Body = $body
        $mailMessage.IsBodyHtml = $true
        $mailMessage.BodyEncoding = [System.Text.Encoding]::UTF8

        $smtpClient = New-Object System.Net.Mail.SmtpClient($SmtpServer, $Port)
        try {
            $smtpClient.EnableSsl = $false
            switch ($EncryptionType) {
                'StartTLS' { $smtpClient.EnableSsl = $true }
                'SSL/TLS' { $smtpClient.EnableSsl = $true }
            }

            $smtpClient.UseDefaultCredentials = $false
            $smtpClient.Credentials = $Credential.GetNetworkCredential()
            $smtpClient.Send($mailMessage)
        } finally {
            if ($null -ne $smtpClient) {
                $smtpClient.Dispose()
            }
        }
    } finally {
        if ($null -ne $mailMessage) {
            $mailMessage.Dispose()
        }
    }
}
