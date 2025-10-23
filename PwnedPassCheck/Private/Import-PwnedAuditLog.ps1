function Import-PwnedAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $entries = New-Object System.Collections.Specialized.OrderedDictionary
    $metadata = New-Object System.Collections.Specialized.OrderedDictionary

    if (-not (Test-Path -Path $Path)) {
        return [pscustomobject]@{
            Entries  = $entries
            Metadata = $metadata
        }
    }

    try {
        $rawContent = Get-Content -Path $Path -Raw -ErrorAction Stop
    } catch {
        throw "Unable to read audit log '$Path': $_"
    }

    if (-not $rawContent.Trim()) {
        return [pscustomobject]@{
            Entries  = $entries
            Metadata = $metadata
        }
    }

    try {
        $parsedContent = $rawContent | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Audit log '$Path' could not be parsed as JSON: $_"
    }

    if ($parsedContent -and $parsedContent.Entries) {
        foreach ($entryProperty in $parsedContent.Entries.PSObject.Properties) {
            $entryValue = $entryProperty.Value
            if ($entryValue -is [System.Collections.IDictionary]) {
                $orderedEntry = New-Object System.Collections.Specialized.OrderedDictionary
                foreach ($property in $entryValue.GetEnumerator()) {
                    $orderedEntry[$property.Key] = $property.Value
                }
                $entries[$entryProperty.Name] = $orderedEntry
            } else {
                $entries[$entryProperty.Name] = $entryValue
            }
        }
    }

    if ($parsedContent -and $parsedContent.PSObject.Properties['Metadata']) {
        $metadataValue = $parsedContent.Metadata
        if ($metadataValue -is [System.Collections.IDictionary]) {
            foreach ($item in $metadataValue.GetEnumerator()) {
                $metadata[$item.Key] = $item.Value
            }
        } elseif ($metadataValue) {
            foreach ($property in $metadataValue.PSObject.Properties) {
                $metadata[$property.Name] = $property.Value
            }
        }
    }

    return [pscustomobject]@{
        Entries  = $entries
        Metadata = $metadata
    }
}
