function Export-PwnedAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Entries,
        [System.Collections.IDictionary]$Metadata
    )

    $logObject = New-Object System.Collections.Specialized.OrderedDictionary
    $logObject['GeneratedOn'] = (Get-Date).ToUniversalTime().ToString('o')

    $orderedEntries = New-Object System.Collections.Specialized.OrderedDictionary
    foreach ($key in $Entries.Keys) {
        $orderedEntries[$key] = $Entries[$key]
    }

    $logObject['Entries'] = $orderedEntries

    if ($PSBoundParameters.ContainsKey('Metadata') -and $Metadata) {
        $orderedMetadata = New-Object System.Collections.Specialized.OrderedDictionary
        foreach ($key in $Metadata.Keys) {
            $orderedMetadata[$key] = $Metadata[$key]
        }
        $logObject['Metadata'] = $orderedMetadata
    }

    $json = $logObject | ConvertTo-Json -Depth 6

    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -Path $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    Set-Content -Path $Path -Value $json

    return Get-Item -Path $Path
}
