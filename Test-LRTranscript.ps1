#Requires -Version 7.2
<#
.SYNOPSIS
    Verifies the hash chain in an Invoke-MdeLiveResponse.ps1 session transcript.

.DESCRIPTION
    Each transcript line carries 'prev', the SHA-256 of the line before it. This walks the
    file and reports the first line whose 'prev' does not match, which means a line was
    edited, inserted or removed above it. Lines cut off the end leave no trace in the
    chain, so compare the reported final hash with the one printed when the session ended.

.EXAMPLE
    ./Test-LRTranscript.ps1 ./lr-sessions/lr-session-20261001-142233.jsonl
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Path)

$ErrorActionPreference = 'Stop'

$prev = $null
$n = 0
foreach ($line in Get-Content -LiteralPath $Path) {
    $n++
    if (-not $line) { continue }
    $entry = $line | ConvertFrom-Json
    # Lines written before chaining existed have no prev field; a chain starts after them.
    $hasPrev = $entry.PSObject.Properties.Name -contains 'prev'
    if ($hasPrev -and $entry.prev -ne $prev) {
        Write-Output ([pscustomobject]@{ Valid = $false; Lines = $n; BrokenAtLine = $n; FinalHash = $null })
        exit 1
    }
    $prev = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($line))).ToLower()
}

Write-Output ([pscustomobject]@{ Valid = $true; Lines = $n; BrokenAtLine = $null; FinalHash = $prev })
