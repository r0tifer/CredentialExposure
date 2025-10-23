function Test-ValidHibpApiKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ApiKey,
        [switch]$ThrowOnFail
    )

    if ($null -eq $ApiKey) {
        if ($ThrowOnFail) {
            throw "HIBP API key must be a 32-character hexadecimal string."
        }

        return $false
    }

    $normalizedKey = $ApiKey.Trim()
    if (-not $normalizedKey) {
        if ($ThrowOnFail) {
            throw "HIBP API key must be a 32-character hexadecimal string."
        }

        return $false
    }

    if ($normalizedKey -notmatch '^(?i:[0-9a-f]{32})$') {
        if ($ThrowOnFail) {
            throw "HIBP API key must be a 32-character hexadecimal string."
        }

        return $false
    }

    return $true
}
