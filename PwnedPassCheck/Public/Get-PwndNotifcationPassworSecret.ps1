function Get-ExposureNotificationSecret {
    <#
    .SYNOPSIS
    Generates an encrypted password string suitable for EmailUserPassword in the settings file.

    .DESCRIPTION
    Prompts for the notification account password using Read-Host -AsSecureString, encrypts it
    with DPAPI via ConvertFrom-SecureString, and writes the ciphertext to the pipeline. The
    encrypted value can be pasted into the EmailUserPassword property of PwnedPassCheckSettings.psd1.

    .OUTPUTS
    System.String. An encrypted string that can only be decrypted by the account that generated it.
    #>
    [CmdletBinding()]
    param(
        # When provided, skip the prompt and use this secure string as the source password.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [System.Security.SecureString]$SecurePassword
    )

    process {
        $passwordToProtect = $SecurePassword
        if (-not $passwordToProtect) {
            $passwordToProtect = Read-Host -AsSecureString -Prompt 'Enter the password for the notification account'
            $confirmation = Read-Host -AsSecureString -Prompt 'Confirm the password'

            $primaryPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordToProtect)
            $secondaryPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmation)
            try {
                $primary = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($primaryPtr)
                $secondary = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secondaryPtr)
                if ($primary -ne $secondary) {
                    throw "The entered passwords do not match. Please try again."
                }
            } finally {
                if ($primaryPtr -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($primaryPtr)
                }
                if ($secondaryPtr -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secondaryPtr)
                }
            }
        }

        try {
            $protected = ConvertFrom-SecureString -SecureString $passwordToProtect
            return $protected
        } catch {
            throw "Failed to encrypt the notification password: $_"
        }
    }
}
