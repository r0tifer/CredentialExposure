function Send-PwnedUserNotification {
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
        [string]$ToAddress,
        [Parameter(Mandatory)]
        [string]$RecipientDisplayName,
        [Parameter(Mandatory)]
        [string]$SamAccountName,
        [Parameter(Mandatory)]
        [datetime]$DetectionTimeUtc,
        [Parameter(Mandatory)]
        [int]$SeenCount,
        [Parameter(Mandatory)]
        [int]$NotificationCount,
        [Parameter(Mandatory)]
        [System.Net.NetworkCredential]$Credential
    )

    $subject = 'Action Required: Reset Your Compromised Password'
    $localDetectionTime = $DetectionTimeUtc.ToLocalTime()

    $notificationLine = "This is notification number $NotificationCount regarding this matter."
    if ($NotificationCount -eq 1) {
        $notificationLine = 'This is the first notification we have sent regarding this matter.'
    }

    $body = @"
Hello $RecipientDisplayName,

Our security monitoring detected on $($localDetectionTime.ToString('f')) that the password for your domain account '$SamAccountName' appears in known data breaches. $notificationLine

What you need to do right now:
1. Press Ctrl+Alt+Del while signed in to a company-managed workstation.
2. Select "Change a password."
3. Enter your current password when prompted.
4. Enter and confirm a new, unique password that you have not used elsewhere.
5. Press Enter to complete the change.

The compromised password has been observed $SeenCount time(s) in published breach data. Acting quickly helps protect both you and the organization. You will receive no more than one reminder per day while this issue remains unresolved.

If you encounter any issues changing your password, please contact the Service Desk for assistance immediately.

Thank you for your prompt attention to this matter.
"@

    $mailMessage = New-Object System.Net.Mail.MailMessage
    try {
        $mailMessage.From = New-Object System.Net.Mail.MailAddress($FromAddress)
        $mailMessage.To.Add((New-Object System.Net.Mail.MailAddress($ToAddress, $RecipientDisplayName)))
        $mailMessage.Subject = $subject
        $mailMessage.Body = $body
        $mailMessage.IsBodyHtml = $false
        $mailMessage.BodyEncoding = [System.Text.Encoding]::UTF8

        $smtpClient = New-Object System.Net.Mail.SmtpClient($SmtpServer, $Port)
        try {
            $smtpClient.EnableSsl = $false
            switch ($EncryptionType) {
                'StartTLS' { $smtpClient.EnableSsl = $true }
                'SSL/TLS' { $smtpClient.EnableSsl = $true }
            }

            $smtpClient.UseDefaultCredentials = $false
            $smtpClient.Credentials = $Credential
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
