#Requires -Version 7.2
<#
.SYNOPSIS
    Interactive, browser-free Microsoft Defender for Endpoint (MDE) Live Response client.

.DESCRIPTION
    Presents a REPL-style prompt against a single onboarded device using the documented
    Live Response API. Each command you type is submitted as a machine action
    (PutFile / RunScript / GetFile), polled to completion, and its result streamed back
    to your console or written to disk.

    This is NOT the portal's interactive console. Microsoft does not publish an API for
    that channel. The supported API accepts only PutFile, RunScript and GetFile, in that
    order, per action. Arbitrary command execution therefore goes through a small wrapper
    script that must already exist in your tenant's Live Response library
    (see Invoke-LRCommand.ps1, and 'library upload' below).

.PREREQUISITES
    - Live Response enabled under Settings > Endpoints > Advanced features.
      "Live response unsigned script execution" must also be on if your library scripts
      are unsigned.
    - Entra app registration with application permissions:
        Machine.LiveResponse   (to submit actions)
        Machine.ReadWrite.All  (to retrieve action results, and to resolve device names)
        Library.Manage         (only if you use the 'library' commands)
      Machine.LiveResponse alone submits actions but is refused on
      GetLiveResponseResultDownloadLink, so every command appears to run with no output.
      Admin consent granted.
    - The target device's RBAC device group needs a remediation level assigned.

.NOTES
    Rate limits (as documented): 10 runliveresponse calls/min, 25 concurrent sessions
    tenant-wide, one session per device at a time, RunScript times out at 10 minutes.
    All actions are logged tenant-side and appear in the Action center. This script also
    writes a local JSONL transcript for your own case notes.

.EXAMPLE
    ./Invoke-MdeLiveResponse.ps1 -TenantId $tid -ClientId $cid -DeviceName ws-eng-042
#>
[CmdletBinding(DefaultParameterSetName = 'Secret')]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,

    # App-only with a client secret. Omit to read $env:MDE_CLIENT_SECRET, else prompt.
    [Parameter(ParameterSetName = 'Secret')][securestring]$ClientSecret,

    # App-only with a certificate (preferred: no shared secret at rest).
    [Parameter(ParameterSetName = 'Certificate', Mandatory)][string]$CertificatePath,
    [Parameter(ParameterSetName = 'Certificate')][securestring]$CertificatePassword,

    # Delegated sign-in. Needs a browser on some device to enter the code.
    [Parameter(ParameterSetName = 'DeviceCode', Mandatory)][switch]$UseDeviceCode,

    [string]$DeviceName,
    [string]$MachineId,

    [ValidateSet('Commercial', 'UsGovGcc', 'UsGovGccHigh', 'UsGovDoD')]
    [string]$Cloud = 'Commercial',

    # Override the API host, e.g. https://eu.api.security.microsoft.com for lower latency.
    [string]$ApiBaseUri,

    [string]$CommandWrapperScript = 'Invoke-LRCommand.ps1',
    [string]$DownloadPath = (Join-Path (Get-Location) 'lr-downloads'),
    [string]$LogPath,
    [int]$PollIntervalSeconds = 5,
    [int]$ActionTimeoutMinutes = 15,
    [string]$Comment = 'Live Response via Invoke-MdeLiveResponse.ps1'
)

# Deliberately 1.0, not Latest. Strict mode 2.0+ throws on references to properties the
# API omits, and machineaction responses drop fields like commands and errorHResult
# depending on action type and status. It also disables the scalar .Count fallback.
Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

#region Cloud endpoints -------------------------------------------------------

$CloudMap = @{
    # api.securitycenter.microsoft.com matches the token audience and is the documented base
    # for these endpoints. api.security.microsoft.com also answers, but mixing hosts adds a
    # replication hop that shows up as 404s on freshly created machine actions.
    Commercial   = @{ Api = 'https://api.securitycenter.microsoft.com';     Resource = 'https://api.securitycenter.microsoft.com';      Authority = 'https://login.microsoftonline.com' }
    UsGovGcc     = @{ Api = 'https://api-gcc.securitycenter.microsoft.us';  Resource = 'https://api-gcc.securitycenter.microsoft.us';   Authority = 'https://login.microsoftonline.com' }
    UsGovGccHigh = @{ Api = 'https://api-gov.securitycenter.microsoft.us';  Resource = 'https://api-gov.securitycenter.microsoft.us';   Authority = 'https://login.microsoftonline.us' }
    UsGovDoD     = @{ Api = 'https://api-gov.securitycenter.microsoft.us';  Resource = 'https://api-gov.securitycenter.microsoft.us';   Authority = 'https://login.microsoftonline.us' }
}

$script:Cfg = $CloudMap[$Cloud]
if ($ApiBaseUri) { $script:Cfg.Api = $ApiBaseUri.TrimEnd('/') }

#endregion

#region Helpers ---------------------------------------------------------------

function Write-Status {
    param([string]$Message, [string]$Level = 'Info')
    $color = switch ($Level) {
        'Good' { 'Green' } 'Warn' { 'Yellow' } 'Bad' { 'Red' } 'Dim' { 'DarkGray' } default { 'Cyan' }
    }
    Write-Host $Message -ForegroundColor $color
}

function Write-Transcript {
    param([hashtable]$Entry)
    if (-not $script:LogFile) { return }
    $Entry['timestamp'] = (Get-Date).ToUniversalTime().ToString('o')
    ($Entry | ConvertTo-Json -Depth 6 -Compress) | Add-Content -LiteralPath $script:LogFile
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-GzipOriginalName {
    <# Reads the FNAME field out of a gzip header, if the producer set one. #>
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 12 -or $Bytes[0] -ne 0x1f -or $Bytes[1] -ne 0x8b) { return $null }
    $flg = $Bytes[3]
    if (-not ($flg -band 0x08)) { return $null }          # FNAME not present
    $i = 10                                                # past ID, CM, FLG, MTIME, XFL, OS
    if ($flg -band 0x04) {                                 # skip FEXTRA
        $i += 2 + ($Bytes[$i] + ($Bytes[$i + 1] -shl 8))
    }
    $start = $i
    while ($i -lt $Bytes.Length -and $Bytes[$i] -ne 0) { $i++ }
    if ($i -le $start) { return $null }
    $name = [Text.Encoding]::GetEncoding('ISO-8859-1').GetString($Bytes, $start, $i - $start)
    # Split manually. Split-Path will not break a Windows path when running on Linux.
    ($name -split '[\\/]')[-1]
}

function Remove-ControlCharacter {
    <# Replaces C0/C1 control characters (except TAB, CR, LF) with U+FFFD. RunScript
       output and gzip FNAME fields come from the endpoint, which on a compromised host is
       attacker-controlled; raw escape sequences could otherwise rewrite the analyst's
       terminal or forge lines in the transcript. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    [regex]::Replace($Text, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x80-\x9F]', [string][char]0xFFFD)
}

function Unprotect-SecureString {
    param([securestring]$Secure)
    [System.Net.NetworkCredential]::new('', $Secure).Password
}

#endregion

#region Authentication --------------------------------------------------------

function New-ClientAssertion {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$ClientIdValue,
        [string]$TokenEndpoint
    )
    $now = [DateTimeOffset]::UtcNow
    $header = @{
        alg = 'RS256'
        typ = 'JWT'
        x5t = ConvertTo-Base64Url -Bytes $Certificate.GetCertHash()
    } | ConvertTo-Json -Compress

    $payload = @{
        aud = $TokenEndpoint
        iss = $ClientIdValue
        sub = $ClientIdValue
        jti = [guid]::NewGuid().ToString()
        nbf = [int]$now.ToUnixTimeSeconds()
        exp = [int]$now.AddMinutes(10).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    $unsigned = '{0}.{1}' -f
        (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))),
        (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload)))

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) { throw 'Certificate has no usable RSA private key.' }
    $sig = $rsa.SignData(
        [Text.Encoding]::UTF8.GetBytes($unsigned),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    '{0}.{1}' -f $unsigned, (ConvertTo-Base64Url $sig)
}

function Request-Token {
    <# Acquires a fresh token using whichever credential flow was selected. #>
    $tokenEndpoint = '{0}/{1}/oauth2/token' -f $script:Cfg.Authority, $TenantId

    switch ($script:AuthMode) {
        'Certificate' {
            # Not $pwd: that is the automatic working-directory variable.
            $certPlain = if ($CertificatePassword) { Unprotect-SecureString $CertificatePassword } else { $null }
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                (Resolve-Path -LiteralPath $CertificatePath).Path, $certPlain,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
            $body = @{
                grant_type            = 'client_credentials'
                client_id             = $ClientId
                resource              = $script:Cfg.Resource
                client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                client_assertion      = New-ClientAssertion -Certificate $cert -ClientIdValue $ClientId -TokenEndpoint $tokenEndpoint
            }
            $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body
        }

        'DeviceCode' {
            $dcEndpoint = '{0}/{1}/oauth2/devicecode' -f $script:Cfg.Authority, $TenantId
            $dc = Invoke-RestMethod -Method Post -Uri $dcEndpoint -Body @{
                client_id = $ClientId
                resource  = $script:Cfg.Resource
            }
            Write-Status $dc.message 'Warn'
            $dcInterval = if ($dc.PSObject.Properties.Name -contains 'interval' -and [int]$dc.interval -gt 0) {
                [int]$dc.interval } else { 5 }
            $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
            $resp = $null
            while (-not $resp -and (Get-Date) -lt $deadline) {
                Start-Sleep -Seconds $dcInterval
                try {
                    $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body @{
                        grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                        client_id   = $ClientId
                        resource    = $script:Cfg.Resource
                        device_code = $dc.device_code
                    }
                } catch {
                    $detail = $_.ErrorDetails.Message
                    if ($detail -notmatch 'authorization_pending|slow_down') { throw }
                }
            }
            if (-not $resp) { throw 'Device code flow timed out.' }
        }

        default {
            if (-not $ClientSecret) {
                if ($env:MDE_CLIENT_SECRET) {
                    $ClientSecret = ConvertTo-SecureString $env:MDE_CLIENT_SECRET -AsPlainText -Force
                } else {
                    $ClientSecret = Read-Host -Prompt 'Client secret' -AsSecureString
                }
            }
            $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body @{
                grant_type    = 'client_credentials'
                client_id     = $ClientId
                client_secret = Unprotect-SecureString $ClientSecret
                resource      = $script:Cfg.Resource
            }
        }
    }

    $script:AccessToken = $resp.access_token
    $script:TokenExpiry = (Get-Date).AddSeconds([int]$resp.expires_in - 120)
}

function Get-AccessToken {
    if (-not $script:AccessToken -or (Get-Date) -ge $script:TokenExpiry) { Request-Token }
    $script:AccessToken
}

#endregion

#region API plumbing ----------------------------------------------------------

function Invoke-MdeApi {
    param(
        [ValidateSet('GET', 'POST', 'DELETE')][string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        $Body,
        [hashtable]$Form,
        [int]$MaxRetries = 4
    )
    $uri = if ($Path -match '^https?://') { $Path } else { '{0}/{1}' -f $script:Cfg.Api, $Path.TrimStart('/') }
    $refreshed = $false

    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        $params = @{
            Method              = $Method
            Uri                 = $uri
            Headers             = @{ Authorization = "Bearer $(Get-AccessToken)"; Accept = 'application/json' }
            SkipHttpErrorCheck  = $true
            MaximumRedirection  = 5
            TimeoutSec          = 100
        }
        if ($Form) {
            $params.Form = $Form
        } elseif ($null -ne $Body) {
            $params.Body        = ($Body | ConvertTo-Json -Depth 8)
            $params.ContentType = 'application/json'
        }

        $resp = Invoke-WebRequest @params
        $code = [int]$resp.StatusCode

        if ($code -ge 200 -and $code -lt 300) {
            if ([string]::IsNullOrWhiteSpace($resp.Content)) { return $null }
            return ($resp.Content | ConvertFrom-Json)
        }

        if ($code -eq 429) {
            $wait = 0
            $ra = $resp.Headers.GetEnumerator() | Where-Object { $_.Key -ieq 'Retry-After' } |
                  Select-Object -First 1
            if ($ra) { $wait = [int]($ra.Value | Select-Object -First 1) }
            if ($wait -le 0) { $wait = [Math]::Min(60, [Math]::Pow(2, $attempt + 2)) }
            Write-Status "Throttled (429). Waiting ${wait}s..." 'Warn'
            Start-Sleep -Seconds $wait
            continue
        }

        # Refresh the token once per call
        if ($code -eq 401 -and -not $refreshed) {
            $refreshed = $true
            $script:AccessToken = $null
            continue
        }

        $msg = $resp.Content
        try {
            $err = $resp.Content | ConvertFrom-Json
            if ($err.error) { $msg = '{0}: {1}' -f $err.error.code, $err.error.message }
        } catch { }
        throw ('HTTP {0} on {1} {2} -- {3}' -f $code, $Method, $uri, $msg)
    }
    throw "Gave up after $MaxRetries retries on $Method $uri"
}

function Resolve-MdeMachine {
    param([string]$Name, [string]$Id)

    if ($Id) { return Invoke-MdeApi -Path "api/machines/$Id" }

    # OData string literals escape a single quote by doubling it.
    $literal = $Name.ToLower().Replace("'", "''")
    $filter = [uri]::EscapeDataString("startswith(computerDnsName,'$literal')")
    $hits = (Invoke-MdeApi -Path "api/machines?`$filter=$filter").value

    if (-not $hits) { throw "No onboarded device matches '$Name'." }

    $active = @($hits | Sort-Object { [datetime]$_.lastSeen } -Descending)
    if ($active.Count -gt 1) {
        Write-Status "$($active.Count) devices matched '$Name':" 'Warn'
        $i = 0
        foreach ($m in $active) {
            Write-Host ('  [{0}] {1,-32} {2,-14} last seen {3}  health={4}' -f
                $i++, $m.computerDnsName, $m.osPlatform, $m.lastSeen, $m.healthStatus)
        }
        $pick = Read-Host 'Select index'
        return $active[[int]$pick]
    }
    $active[0]
}

#endregion

#region Live Response actions -------------------------------------------------

function Invoke-LiveResponseAction {
    <# Submits one machine action containing 1..n commands and waits for it. #>
    param([Parameter(Mandatory)][array]$Commands, [string]$ActionComment = $Comment)

    $body = @{ Commands = $Commands; Comment = $ActionComment }
    Write-Transcript @{ event = 'submit'; machine = $script:Machine.id; commands = $Commands }

    try {
        $action = Invoke-MdeApi -Method POST -Path "api/machines/$($script:Machine.id)/runliveresponse" -Body $body
    } catch {
        if ($_.Exception.Message -match 'ActiveRequestAlreadyExists') {
            Write-Status 'A Live Response action is already running on this device. Wait for it, or use "cancel <actionId>".' 'Bad'
            return $null
        }
        throw
    }

    Write-Status "action $($action.id) queued" 'Dim'
    Wait-MdeMachineAction -ActionId $action.id
}

function Wait-MdeMachineAction {
    param([Parameter(Mandatory)][string]$ActionId)

    $deadline = (Get-Date).AddMinutes($ActionTimeoutMinutes)
    # Machine action records are eventually consistent. A poll issued seconds after the
    # POST can hit a replica that has not seen it yet and 404. Tolerate that briefly.
    $notFoundUntil = (Get-Date).AddSeconds(120)
    $spin = '|/-\'
    $n = 0
    $last = ''

    while ((Get-Date) -lt $deadline) {
        try {
            $action = Invoke-MdeApi -Path "api/machineactions/$ActionId"
        } catch {
            if ($_.Exception.Message -match 'HTTP 404' -and (Get-Date) -lt $notFoundUntil) {
                Write-Host ("`r  {0} action not yet visible, retrying..." -f $spin[$n++ % 4]) `
                    -NoNewline -ForegroundColor DarkGray
                Start-Sleep -Seconds $PollIntervalSeconds
                continue
            }
            if ($_.Exception.Message -match 'HTTP 404') {
                Write-Host ''
                Write-Status "Action $ActionId still not visible after 2 min. Check the Action center, or 'actions'." 'Bad'
                return $null
            }
            throw
        }

        if ($action.status -ne $last) {
            Write-Host ''
            Write-Status "  status: $($action.status)" 'Dim'
            $last = $action.status
        } else {
            Write-Host ("`r  {0} waiting..." -f $spin[$n++ % 4]) -NoNewline -ForegroundColor DarkGray
        }

        if ($action.status -in @('Succeeded', 'Failed', 'TimeOut', 'Cancelled')) {
            Write-Host ''
            Write-Transcript @{ event = 'complete'; actionId = $ActionId; status = $action.status }
            return $action
        }
        Start-Sleep -Seconds $PollIntervalSeconds
    }

    Write-Host ''
    Write-Status "Timed out locally after $ActionTimeoutMinutes min. The action may still complete server-side: 'actions' to check." 'Warn'
    $null
}

function Show-ActionResults {
    <# Pulls each command's result. PutFile produces none. #>
    # Not Mandatory: the callers legitimately pass $null when an action was never
    # created or never became visible, and Mandatory refuses to bind $null.
    param($Action)

    if (-not $Action) { return }

    $hasCommands = $Action.PSObject.Properties.Name -contains 'commands'
    if ($hasCommands -and $Action.commands) {
        $index = 0
        foreach ($cmd in $Action.commands) {
            $type = $cmd.command.type
            $state = $cmd.commandStatus
            Write-Status ("[{0}] {1} -> {2}" -f $index, $type, $state) 'Dim'

            # Only PutFile has no result. A Failed RunScript normally still produced
            # output explaining the failure, so fetch it anyway.
            if ($type -eq 'PutFile') { $index++; continue }

            try {
                $link = (Invoke-MdeApi -Path "api/machineactions/$($Action.id)/GetLiveResponseResultDownloadLink(index=$index)").value
                Receive-LiveResponseResult -Url $link -CommandType $type -ActionId $Action.id -Index $index
            } catch {
                Write-Status "  could not fetch result index $index -- $($_.Exception.Message)" 'Warn'
            }
            $index++
        }
    }

    if ($Action.status -ne 'Succeeded' -and
        ($Action.PSObject.Properties.Name -contains 'errorHResult') -and $Action.errorHResult) {
        Write-Status "  errorHResult: $($Action.errorHResult)" 'Bad'
    }
}

function Receive-LiveResponseResult {
    param([string]$Url, [string]$CommandType, [string]$ActionId, [int]$Index)

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("lr_{0}_{1}.bin" -f $ActionId, $Index)
    Invoke-WebRequest -Uri $Url -OutFile $tmp -MaximumRedirection 5 | Out-Null

    $bytes = [IO.File]::ReadAllBytes($tmp)
    $isGzip = $bytes.Length -gt 2 -and $bytes[0] -eq 0x1f -and $bytes[1] -eq 0x8b

    if ($CommandType -eq 'GetFile') {
        if (-not (Test-Path $DownloadPath)) { New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null }
        $stem = '{0}_{1}_{2}' -f $script:Machine.computerDnsName, $ActionId.Substring(0, 8), $Index
        if ($isGzip) {
            $orig = Get-GzipOriginalName -Bytes $bytes
            # FNAME is endpoint-supplied. Strip anything that is not a plain filename char.
            if ($orig) { $orig = [regex]::Replace($orig, '[\x00-\x1f<>:"/\\|?*]', '_') }
            $leaf = if ($orig) { '{0}_{1}' -f $stem, $orig } else { $stem }
            $out = Join-Path $DownloadPath $leaf
            $in = [IO.File]::OpenRead($tmp)
            $gz = [IO.Compression.GZipStream]::new($in, [IO.Compression.CompressionMode]::Decompress)
            $fs = [IO.File]::Create($out)
            $gz.CopyTo($fs); $fs.Dispose(); $gz.Dispose(); $in.Dispose()
            Write-Status "  collected -> $out ($([math]::Round((Get-Item $out).Length/1KB,1)) KB, ungzipped)" 'Good'
        } else {
            $out = Join-Path $DownloadPath "$stem.bin"
            Copy-Item $tmp $out -Force
            Write-Status "  collected -> $out" 'Good'
        }
        Remove-Item $tmp -Force
        Write-Transcript @{ event = 'getfile'; actionId = $ActionId; savedTo = $out }
        return
    }

    # RunScript: result is text (usually JSON with script_output / script_errors)
    $text = if ($isGzip) {
        $in = [IO.File]::OpenRead($tmp)
        $gz = [IO.Compression.GZipStream]::new($in, [IO.Compression.CompressionMode]::Decompress)
        $sr = [IO.StreamReader]::new($gz)
        $t = $sr.ReadToEnd(); $sr.Dispose(); $gz.Dispose(); $in.Dispose(); $t
    } else {
        [IO.File]::ReadAllText($tmp)
    }
    Remove-Item $tmp -Force

    # Remove terminal escape sequences before they reach the console, the 'last' cache, or the transcript.
    $text = Remove-ControlCharacter $text

    $printed = $false
    try {
        $json = $text | ConvertFrom-Json
        foreach ($field in 'script_output', 'output', 'script_errors', 'errors', 'exit_code') {
            if ($json.PSObject.Properties.Name -contains $field) {
                # Sanitize decoded JSON string
                $val = Remove-ControlCharacter "$($json.$field)"
                if ($null -ne $val -and "$val".Trim()) {
                    $lvl = if ($field -match 'error') { 'Bad' } else { 'Dim' }
                    if ($field -match 'output') { Write-Host $val } else { Write-Status ("  {0}: {1}" -f $field, $val) $lvl }
                    $printed = $true
                }
            }
        }
    } catch { }

    if (-not $printed) { Write-Host $text }
    $script:LastResult = $text
    Write-Transcript @{ event = 'runscript_result'; actionId = $ActionId; bytes = $text.Length }
}

#endregion

#region REPL ------------------------------------------------------------------

function Show-Help {
    @'
  Device / session
    machine                       show target device details
    open <name|id>                retarget another device
    actions [n]                   recent machine actions on this device
    cancel <actionId> [comment]   cancel a pending action
    comment <text>                set the audit comment applied to new actions
    last                          reprint the last RunScript output
    result <actionId> [index]     re-fetch the output of any past action
    help | exit

  Library (needs Library.Manage)
    library                       list library files
    library upload <path> [desc]  upload a script/tool to the tenant LR library
    library delete <fileName>     remove a library file

  Execution
    run <ScriptName> [args]       RunScript from the library (10 min cap)
    cmd <powershell>              run arbitrary PowerShell via the wrapper script
    get <remote\path>             GetFile from the device
    put <libraryFileName>         PutFile from the library to the device working dir

  Chaining (one action = one session, avoids re-queuing)
    run <ScriptName> [args] --get <remote\path>
    put <file> --run <ScriptName> [args] --get <remote\path>
'@
}

function Split-CommandLine {
    # Emits one string per token, quotes stripped. With -AsObject, emits one object per
    # token with Text (quotes stripped) and Quoted (was it wrapped in double quotes), so
    # callers can tell a literal "--get" argument from the --get chain separator.
    # Callers MUST wrap in @() so a single token stays an array: without it, $parts[0]
    # returns one character and $parts.Count fails.
    # Do not use -NoEnumerate here. It nests inside the callers' @() wrappers.
    param([string]$Line, [switch]$AsObject)
    [regex]::Matches($Line, '"([^"]*)"|(\S+)') | ForEach-Object {
        $quoted = $_.Groups[1].Success
        $text = if ($quoted) { $_.Groups[1].Value } else { $_.Groups[2].Value }
        if ($AsObject) { [pscustomobject]@{ Text = $text; Quoted = $quoted } } else { $text }
    }
}

function Build-ChainedCommands {
    <# Parses a line with optional --put/--run/--get segments into an ordered command array.
       Only an unquoted --put/--run/--get starts a segment; a quoted "--get" is an ordinary
       argument. Quoted tokens keep their internal spacing and are re-quoted in Args so the
       script on the endpoint receives them as one argument, as typed. #>
    param([string]$Line)

    $segments = [ordered]@{}
    $current = $null

    foreach ($tok in @(Split-CommandLine $Line -AsObject)) {
        if (-not $tok.Quoted -and $tok.Text -in '--put', '--run', '--get') {
            $current = $tok.Text.TrimStart('-')
            # A repeated separator replaces the earlier segment (last one wins).
            $segments[$current] = [System.Collections.Generic.List[object]]::new()
        } elseif ($current) {
            $segments[$current].Add($tok)
        }
        # Tokens before the first separator have nowhere to go and are dropped.
    }

    # Fail locally rather than submit a PutFile/GetFile with an empty value, which
    # would burn a session round-trip only to be rejected server-side.
    foreach ($key in @($segments.Keys)) {
        $hasValue = @($segments[$key] | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Text) }).Count -gt 0
        if (-not $hasValue) { throw "--$key requires a value." }
    }

    $commands = @()
    if ($segments.Contains('put')) {
        $name = @($segments['put'] | ForEach-Object Text) -join ' '
        $commands += @{ type = 'PutFile'; params = @(@{ key = 'FileName'; value = $name }) }
    }
    if ($segments.Contains('run')) {
        $parts = @($segments['run'])
        if ([string]::IsNullOrWhiteSpace($parts[0].Text)) { throw 'run requires a script name from the library.' }
        $p = @(@{ key = 'ScriptName'; value = $parts[0].Text })
        if ($parts.Count -gt 1) {
            $argTokens = foreach ($t in $parts[1..($parts.Count - 1)]) {
                if ($t.Quoted) { '"{0}"' -f $t.Text } else { $t.Text }
            }
            $p += @{ key = 'Args'; value = (@($argTokens) -join ' ') }
        }
        $commands += @{ type = 'RunScript'; params = $p }
    }
    if ($segments.Contains('get')) {
        $path = @($segments['get'] | ForEach-Object Text) -join ' '
        $commands += @{ type = 'GetFile'; params = @(@{ key = 'Path'; value = $path }) }
    }
    $commands
}

function Start-Repl {
    Write-Host ''
    Write-Status "Live Response session context established." 'Good'
    Write-Host ("  device : {0}  ({1})" -f $script:Machine.computerDnsName, $script:Machine.osPlatform)
    Write-Host ("  id     : {0}" -f $script:Machine.id)
    Write-Host ("  health : {0}   last seen {1}" -f $script:Machine.healthStatus, $script:Machine.lastSeen)
    Write-Host ("  log    : {0}" -f $script:LogFile) -ForegroundColor DarkGray
    Write-Host '  Type "help" for commands. Each command is a tenant-logged machine action.' -ForegroundColor DarkGray
    Write-Host ''

    while ($true) {
        $prompt = '{0}> ' -f $script:Machine.computerDnsName
        Write-Host $prompt -NoNewline -ForegroundColor Cyan
        $line = Read-Host
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $tokens = @(Split-CommandLine $line)
        $verb = ([string]$tokens[0]).ToLower()
        $rest = if ($tokens.Count -gt 1) { ($tokens[1..($tokens.Count - 1)] -join ' ') } else { '' }
        # $rest has been through the tokenizer, which strips quotes. Verbs that forward
        # free text to the endpoint need the line exactly as typed.
        $rawRest = if ($line -match '^\s*\S+\s+(.+)$') { $Matches[1].Trim() } else { '' }

        try {
            switch ($verb) {
                { $_ -in 'exit', 'quit' } { Write-Status 'Closing local session. Queued actions continue server-side.' 'Dim'; return }
                'help' { Show-Help; continue }

                'machine' {
                    $script:Machine | Select-Object computerDnsName, id, osPlatform, version, healthStatus,
                        riskScore, exposureLevel, lastIpAddress, lastExternalIpAddress, lastSeen, rbacGroupName |
                        Format-List
                    continue
                }

                'open' {
                    if (-not $rest) { Write-Status 'Usage: open <deviceName|machineId>' 'Warn'; continue }
                    $script:Machine = if ($rest -match '^(?i)[0-9a-f]{40}$') {
                        Resolve-MdeMachine -Id $rest
                    } else {
                        Resolve-MdeMachine -Name $rest
                    }
                    Write-Status "Now targeting $($script:Machine.computerDnsName)" 'Good'
                    continue
                }

                'comment' {
                    if ($rawRest) { $script:SessionComment = $rawRest; Write-Status "Comment set." 'Good' }
                    else { Write-Host $script:SessionComment }
                    continue
                }

                'result' {
                    # Re-fetch a past action's output. Useful after a permissions fix, or
                    # when the local session dropped while the action kept running.
                    $parts = @(Split-CommandLine $rest)
                    if (-not $parts) { Write-Status 'Usage: result <actionId> [index]' 'Warn'; continue }
                    $aid = $parts[0]
                    $idx = if ($parts.Count -gt 1 -and $parts[1] -match '^\d+$') { [int]$parts[1] } else { 0 }

                    $act = Invoke-MdeApi -Path "api/machineactions/$aid"
                    $ctype = 'RunScript'
                    if ($act.PSObject.Properties.Name -contains 'commands' -and $act.commands) {
                        $c = @($act.commands)[$idx]
                        if ($c) { $ctype = $c.command.type }
                    }
                    Write-Status "  $($act.status), command $idx is $ctype" 'Dim'

                    $link = (Invoke-MdeApi -Path "api/machineactions/$aid/GetLiveResponseResultDownloadLink(index=$idx)").value
                    Receive-LiveResponseResult -Url $link -CommandType $ctype -ActionId $aid -Index $idx
                    continue
                }

                'last' {
                    if ($script:LastResult) { Write-Host $script:LastResult } else { Write-Status 'No result cached.' 'Warn' }
                    continue
                }

                'actions' {
                    $take = if ($rest -match '^\d+$') { [int]$rest } else { 10 }
                    $filter = [uri]::EscapeDataString("machineId eq '$($script:Machine.id)'")
                    # Grab everything and sort locally
                    $fetch = [Math]::Max(100, $take)
                    @((Invoke-MdeApi -Path "api/machineactions?`$filter=$filter&`$top=$fetch").value) |
                        Sort-Object { [datetime]$_.creationDateTimeUtc } -Descending |
                        Select-Object -First $take |
                        Select-Object id, type, status, requestor, creationDateTimeUtc | Format-Table -AutoSize
                    continue
                }

                    'cancel' {
                    $parts = @(Split-CommandLine $rest)
                    if (-not $parts) { Write-Status 'Usage: cancel <actionId> [comment]' 'Warn'; continue }
                    $c = if ($parts.Count -gt 1) { ($parts[1..($parts.Count - 1)] -join ' ') } else { 'Cancelled by analyst' }
                    Invoke-MdeApi -Method POST -Path "api/machineactions/$($parts[0])/cancel" -Body @{ Comment = $c } | Out-Null
                    Write-Status 'Cancellation requested.' 'Good'
                    continue
                }

                'library' {
                    $parts = @(Split-CommandLine $rest)
                    $sub = if ($parts.Count -gt 0) { ([string]$parts[0]).ToLower() } else { 'list' }
                    switch ($sub) {
                        'upload' {
                            if ($parts.Count -lt 2) { Write-Status 'Usage: library upload <path> [description]' 'Warn'; continue }
                            $file = (Resolve-Path -LiteralPath $parts[1]).Path
                            $desc = if ($parts.Count -gt 2) { ($parts[2..($parts.Count - 1)] -join ' ') } else { 'Uploaded by Invoke-MdeLiveResponse.ps1' }
                            $form = @{
                                file                  = Get-Item -LiteralPath $file
                                Description           = $desc
                                HasParameters         = 'true'
                                ParametersDescription = 'Passed through the Args parameter'
                                OverrideIfExists      = 'true'
                            }
                            Invoke-MdeApi -Method POST -Path 'api/libraryfiles' -Form $form | Out-Null
                            Write-Status "Uploaded $(Split-Path $file -Leaf) to the tenant library." 'Good'
                        }
                        'delete' {
                            if ($parts.Count -lt 2) { Write-Status 'Usage: library delete <fileName>' 'Warn'; continue }
                            $target = [uri]::EscapeDataString($parts[1])
                            Invoke-MdeApi -Method DELETE -Path "api/libraryfiles/$target" | Out-Null
                            Write-Status "Deleted $($parts[1])." 'Good'
                        }
                        default {
                            (Invoke-MdeApi -Path 'api/libraryfiles').value |
                                Select-Object fileName, hasParameters, createdBy, lastUpdatedTime, description |
                                Format-Table -AutoSize
                        }
                    }
                    continue
                }

                'cmd' {
                    if (-not $rawRest) { Write-Status 'Usage: cmd <powershell expression>' 'Warn'; continue }
                    $commands = @(@{
                        type   = 'RunScript'
                        params = @(
                            @{ key = 'ScriptName'; value = $CommandWrapperScript },
                            @{ key = 'Args'; value = $rawRest }
                        )
                    })
                    Show-ActionResults (Invoke-LiveResponseAction -Commands $commands -ActionComment $script:SessionComment)
                    continue
                }

                { $_ -in 'run', 'get', 'put' } {
                    # Normalize "run X args --get Y" into the chained form. Use the raw text
                    # so quotes survive to Build-ChainedCommands, which needs them to tell a
                    # literal "--get" argument from the chain separator.
                    $normalized = '--{0} {1}' -f $verb, $rawRest
                    $commands = @(Build-ChainedCommands $normalized)
                    if (-not $commands) { Write-Status 'Nothing to submit.' 'Warn'; continue }
                    Show-ActionResults (Invoke-LiveResponseAction -Commands $commands -ActionComment $script:SessionComment)
                    continue
                }

                default {
                    Write-Status "Unknown command '$verb'. The API has no shell passthrough -- use 'cmd <powershell>' or 'help'." 'Warn'
                }
            }
        } catch {
            Write-Status "! $($_.Exception.Message)" 'Bad'
            Write-Transcript @{ event = 'error'; message = $_.Exception.Message; input = $line }
        }
    }
}

#endregion

#region Entry point -----------------------------------------------------------

if (-not $DeviceName -and -not $MachineId) {
    $DeviceName = Read-Host 'Device name (or machine id)'
}

$script:AuthMode = $PSCmdlet.ParameterSetName
$script:SessionComment = $Comment
$script:LastResult = $null
$script:LogFile = if ($LogPath) { $LogPath } else {
    Join-Path (Get-Location) ('lr-session-{0}.jsonl' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

Write-Status "Authenticating to $($script:Cfg.Api) ($Cloud)..." 'Info'
Request-Token
Write-Status 'Token acquired.' 'Good'

$script:Machine = if ($MachineId) { Resolve-MdeMachine -Id $MachineId } else { Resolve-MdeMachine -Name $DeviceName }

if ($script:Machine.healthStatus -ne 'Active') {
    Write-Status "Device health is '$($script:Machine.healthStatus)'. Actions will queue until it checks in (up to 3 days)." 'Warn'
}

Write-Transcript @{ event = 'session_start'; machine = $script:Machine.computerDnsName; machineId = $script:Machine.id; cloud = $Cloud }
Start-Repl
Write-Transcript @{ event = 'session_end' }

#endregion