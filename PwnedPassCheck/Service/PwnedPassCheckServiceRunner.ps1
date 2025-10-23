param(
    [string]$SettingsPath,
    [string]$AuditLogPath,
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'

function Resolve-Module {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue) {
        Import-Module -Name $Name -ErrorAction Stop | Out-Null
        return
    }

    throw "Required module '$Name' is not installed or accessible to the service account."
}

try {
    Resolve-Module -Name 'PwnedPassCheck'
    Resolve-Module -Name 'DSInternals'
} catch {
    Write-Error $_
    exit 2
}

$invokeParams = @{}
if ($PSBoundParameters.ContainsKey('SettingsPath') -and -not [string]::IsNullOrWhiteSpace($SettingsPath)) {
    $invokeParams.SettingsPath = $SettingsPath
}

if ($PSBoundParameters.ContainsKey('AuditLogPath') -and -not [string]::IsNullOrWhiteSpace($AuditLogPath)) {
    $invokeParams.AuditLogPath = $AuditLogPath
}

if ($Verbose.IsPresent) {
    $invokeParams.Verbose = $true
}

try {
    $results = @(Get-PwnedADUserPassword @invokeParams)
    $totalAccounts = $results.Count
    $compromisedCount = ($results | Where-Object { $_.IsPwned }).Count
    Write-Output ("Audit completed at {0:u}. Accounts processed: {1}; compromised: {2}." -f (Get-Date), $totalAccounts, $compromisedCount)
    exit 0
} catch {
    Write-Error "Get-PwnedADUserPassword failed: $_"
    exit 4
}
