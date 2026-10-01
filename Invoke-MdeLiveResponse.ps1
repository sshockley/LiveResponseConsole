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
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Parameters are read inside nested functions; UseDeviceCode is a parameter-set selector.')]
[CmdletBinding(DefaultParameterSetName = 'Secret')]
param(
    # PSScriptAnalyzer: UseDeviceCode is never read by name because its only job is to
    # select the 'DeviceCode' parameter.
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,

    # App-only with a client secret. Omit to read $env:MDE_CLIENT_SECRET, else prompt.
    [Parameter(ParameterSetName = 'Secret')][securestring]$ClientSecret,

    # App-only with a certificate (preferred: no shared secret at rest).
    [Parameter(ParameterSetName = 'Certificate', Mandatory)][string]$CertificatePath,
    [Parameter(ParameterSetName = 'Certificate')][securestring]$CertificatePassword,

    # App-only with a certificate from the CurrentUser or LocalMachine 'My' store.
    [Parameter(ParameterSetName = 'Thumbprint', Mandatory)][string]$CertificateThumbprint,

    # Delegated sign-in. Needs a browser on some device to enter the code.
    [Parameter(ParameterSetName = 'DeviceCode', Mandatory)][switch]$UseDeviceCode,

    [string]$DeviceName,
    [string]$MachineId,

    [ValidateSet('Commercial', 'UsGovGcc', 'UsGovGccHigh', 'UsGovDoD')]
    [string]$Cloud = 'Commercial',

    # Override the API host, e.g. https://eu.api.security.microsoft.com for lower latency.
    # New actions may 404 there briefly while they replicate (see the note on $CloudMap).
    [string]$ApiBaseUri,

    [string]$CommandWrapperScript = 'Invoke-LRCommand.ps1',
    [string]$DownloadPath = (Join-Path (Get-Location) 'lr-downloads'),
    [string]$LogPath,
    [int]$PollIntervalSeconds = 5,
    [int]$ActionTimeoutMinutes = 15,

    # Cap on an ungzipped GetFile. Past this the gzip is kept as received instead.
    [ValidateRange(1, [int]::MaxValue)][int]$MaxExtractGB = 50,

    # Also save each RunScript result, unsanitized, under -DownloadPath and hash it.
    [switch]$SaveOutput,
    [string]$Comment = 'Live Response via Invoke-MdeLiveResponse.ps1',
    [string[]]$Command
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

function Get-LineHash {
    param([string]$Line)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Line))).ToLower()
}

function Write-Transcript {
    <# Appends one JSON line. Each line carries 'prev', the SHA-256 of the line before it,
       so editing or removing a line breaks the chain (see Test-LRTranscript.ps1). #>
    param([hashtable]$Entry)
    if (-not $script:LogFile) { return }
    $Entry['timestamp'] = (Get-Date).ToUniversalTime().ToString('o')
    $Entry['prev'] = $script:TranscriptHash
    $line = $Entry | ConvertTo-Json -Depth 6 -Compress
    Add-Content -LiteralPath $script:LogFile -Value $line
    $script:TranscriptHash = Get-LineHash $line
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
    <# Replaces C0/C1 control characters (except TAB, CR, LF) and Unicode bidi controls
       with U+FFFD. RunScript output and gzip FNAME fields come from the endpoint, which on
       a compromised host is attacker-controlled; raw escape sequences could otherwise
       rewrite the analyst's terminal or forge lines in the transcript, and bidi overrides
       can make text display in a different order than it actually reads. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure function: returns a sanitized copy of the input string.')]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    [regex]::Replace($Text, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x80-\x9F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]',
        [string][char]0xFFFD)
}

function ConvertTo-SafeFileName {
    <# Replaces anything that is not a plain filename character with '_'. Used for
       endpoint-supplied strings (gzip FNAME, the device's own reported hostname), which
       on a compromised host are attacker-controlled. Covers C1 controls because an
       ISO-8859-1 decode can yield 0x9B (8-bit CSI). #>
    param([string]$Name)
    if (-not $Name) { return $Name }
    [regex]::Replace($Name, '[\x00-\x1f\x7f-\x9f<>:"/\\|?*]', '_')
}

function Copy-StreamBounded {
    <# Copies From to To, stopping once more than Limit bytes have been read. Returns
       $true if the whole stream fit. Guards against gzip bombs from the endpoint. #>
    param([IO.Stream]$From, [IO.Stream]$To, [long]$Limit)
    $buf = [byte[]]::new(1MB)
    $total = 0L
    while (($n = $From.Read($buf, 0, $buf.Length)) -gt 0) {
        $total += $n
        if ($total -gt $Limit) { return $false }
        $To.Write($buf, 0, $n)
    }
    $true
}

function Unprotect-SecureString {
    param([securestring]$Secure)
    [System.Net.NetworkCredential]::new('', $Secure).Password
}

#endregion

#region Authentication --------------------------------------------------------

function New-ClientAssertion {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Builds an in-memory token string; no system state is changed.')]
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

function Get-StoreCertificate {
    <# Finds a certificate by thumbprint in CurrentUser\My, then LocalMachine\My. #>
    param([string]$Thumbprint)
    $tp = $Thumbprint -replace '[\s:]', ''
    foreach ($location in 'CurrentUser', 'LocalMachine') {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $location)
        try {
            $store.Open('ReadOnly, OpenExistingOnly')
            $found = $store.Certificates.Find('FindByThumbprint', $tp, $false)
            if ($found.Count -gt 0) { return $found[0] }
        } catch {
            Write-Verbose "Could not search $location\My: $($_.Exception.Message)"
        } finally {
            $store.Dispose()
        }
    }
    throw "Certificate $tp not found in CurrentUser\My or LocalMachine\My."
}

function Request-Token {
    <# Acquires a fresh token using whichever credential flow was selected. #>
    # The env-var path converts a secret that is already plaintext in the environment into
    # a SecureString
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Wrapping an already-plaintext environment variable; no secret is introduced in source.')]
    param()
    $tokenEndpoint = '{0}/{1}/oauth2/token' -f $script:Cfg.Authority, $TenantId

    switch ($script:AuthMode) {
        { $_ -in 'Certificate', 'Thumbprint' } {
            $cert = if ($script:AuthMode -eq 'Thumbprint') {
                Get-StoreCertificate -Thumbprint $CertificateThumbprint
            } else {
                $certPlain = if ($CertificatePassword) { Unprotect-SecureString $CertificatePassword } else { $null }
                $certFile = (Resolve-Path -LiteralPath $CertificatePath).Path
                $keyFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
                $loader = 'System.Security.Cryptography.X509Certificates.X509CertificateLoader' -as [type]
                if ($loader) {
                    $loader::LoadPkcs12FromFile($certFile, $certPlain, $keyFlags)
                } else {
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certFile, $certPlain, $keyFlags)
                }
            }
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
            $resp = $null
            # Renew silently when possible, so the analyst is not sent back to the browser
            # every time the access token expires.
            if ($script:RefreshToken) {
                try {
                    $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body @{
                        grant_type    = 'refresh_token'
                        client_id     = $ClientId
                        resource      = $script:Cfg.Resource
                        refresh_token = $script:RefreshToken
                    }
                } catch {
                    Write-Status "Token refresh failed ($($_.Exception.Message)); signing in again." 'Warn'
                }
            }

            if (-not $resp) {
                $dcEndpoint = '{0}/{1}/oauth2/devicecode' -f $script:Cfg.Authority, $TenantId
                $dc = Invoke-RestMethod -Method Post -Uri $dcEndpoint -Body @{
                    client_id = $ClientId
                    resource  = $script:Cfg.Resource
                }
                Write-Status $dc.message 'Warn'
                $dcInterval = if ($dc.PSObject.Properties.Name -contains 'interval' -and [int]$dc.interval -gt 0) {
                    [int]$dc.interval } else { 5 }
                $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
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
                        # RFC 8628 3.5: back off by 5 seconds on every slow_down.
                        if ($detail -match 'slow_down') { $dcInterval += 5 }
                    }
                }
                if (-not $resp) { throw 'Device code flow timed out.' }
            }

            # Entra may rotate the refresh token, so always keep the newest one.
            if ($resp.PSObject.Properties.Name -contains 'refresh_token' -and $resp.refresh_token) {
                $script:RefreshToken = $resp.refresh_token
            }
        }

        default {
            # Script scope, so a prompted secret survives to the next token refresh.
            if (-not $script:ClientSecret) {
                if ($env:MDE_CLIENT_SECRET) {
                    $script:ClientSecret = ConvertTo-SecureString $env:MDE_CLIENT_SECRET -AsPlainText -Force
                } else {
                    $script:ClientSecret = Read-Host -Prompt 'Client secret' -AsSecureString
                }
            }
            $resp = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body @{
                grant_type    = 'client_credentials'
                client_id     = $ClientId
                client_secret = Unprotect-SecureString $script:ClientSecret
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

        # Transient gateway errors are retried for GET only. A POST that hit a 504 may
        # already have created its machine action, and resubmitting it is not harmless.
        if ($code -eq 429 -or ($Method -eq 'GET' -and $code -in 502, 503, 504)) {
            $wait = 0
            $ra = $resp.Headers.GetEnumerator() | Where-Object { $_.Key -ieq 'Retry-After' } |
                  Select-Object -First 1
            if ($ra) {
                # Retry-After is either delta-seconds or an HTTP-date.
                $raw = [string]($ra.Value | Select-Object -First 1)
                $secs = 0
                $when = [DateTimeOffset]::MinValue
                if ([int]::TryParse($raw, [ref]$secs)) {
                    $wait = $secs
                } elseif ([DateTimeOffset]::TryParse($raw, [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$when)) {
                    $wait = [int][Math]::Ceiling(($when - [DateTimeOffset]::UtcNow).TotalSeconds)
                }
            }
            if ($wait -le 0) { $wait = [Math]::Min(60, [Math]::Pow(2, $attempt + 2)) }
            $why = if ($code -eq 429) { 'Throttled (429)' } else { "HTTP $code" }
            # Cap the wait so a huge Retry-After cannot stall the session with no way out
            # but Ctrl+C. Retrying early just earns another 429.
            $maxWait = 300
            if ($wait -gt $maxWait) {
                Write-Status "$why. Server asked for ${wait}s; waiting ${maxWait}s instead..." 'Warn'
                $wait = $maxWait
            } else {
                Write-Status "$why. Waiting ${wait}s..." 'Warn'
            }
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
        } catch {
            Write-Verbose "Error body on $Method $uri is not JSON; reporting it verbatim."
        }
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

    # ConvertFrom-Json already yields DateTime here. Casting would throw on a device that
    # has never reported lastSeen.
    $active = @($hits | Sort-Object lastSeen -Descending)

    # startswith also matches longer names (ws-eng-04 hits ws-eng-042). Prefer devices
    # whose FQDN or short hostname is exactly what was typed.
    $exact = @($active | Where-Object {
        $_.computerDnsName -ieq $Name -or ($_.computerDnsName -split '\.')[0] -ieq $Name
    })
    if ($exact.Count -gt 0) { $active = $exact }

    if ($active.Count -gt 1) {
        if ($script:NonInteractive) {
            throw "$($active.Count) devices match '$Name'. Use -MachineId or a more specific name when using -Command."
        }
        Write-Status "$($active.Count) devices matched '$Name':" 'Warn'
        $i = 0
        foreach ($m in $active) {
            Write-Host ('  [{0}] {1,-32} {2,-14} last seen {3}  health={4}' -f
                $i++, $m.computerDnsName, $m.osPlatform, $m.lastSeen, $m.healthStatus)
        }
        $pick = Read-Host 'Select index'
        # Throw rather than return $null, so 'open' keeps the current target.
        if ($pick -notmatch '^\s*\d+\s*$' -or [int]$pick -ge $active.Count) {
            throw "Invalid selection '$pick'."
        }
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
    Write-Transcript @{ event = 'queued'; machine = $script:Machine.id; actionId = $action.id; comment = $ActionComment }
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

    # In a log file (CI, scheduled task) the \r redraws pile up into one huge line, so the
    # spinner only runs on a real console. $drawn tracks a spinner line that needs ending.
    $spinner = -not [Console]::IsOutputRedirected
    $drawn = $false
    $notedInvisible = $false

    while ((Get-Date) -lt $deadline) {
        try {
            $action = Invoke-MdeApi -Path "api/machineactions/$ActionId"
        } catch {
            if ($_.Exception.Message -match 'HTTP 404' -and (Get-Date) -lt $notFoundUntil) {
                if ($spinner) {
                    Write-Host ("`r  {0} action not yet visible, retrying..." -f $spin[$n++ % 4]) `
                        -NoNewline -ForegroundColor DarkGray
                    $drawn = $true
                } elseif (-not $notedInvisible) {
                    Write-Status '  action not yet visible, retrying...' 'Dim'
                    $notedInvisible = $true
                }
                Start-Sleep -Seconds $PollIntervalSeconds
                continue
            }
            if ($_.Exception.Message -match 'HTTP 404') {
                if ($drawn) { Write-Host '' }
                Write-Status "Action $ActionId still not visible after 2 min. Check the Action center, or 'actions'." 'Bad'
                return $null
            }
            throw
        }

        if ($action.status -ne $last) {
            if ($drawn) { Write-Host ''; $drawn = $false }
            Write-Status "  status: $($action.status)" 'Dim'
            $last = $action.status
        } elseif ($spinner) {
            Write-Host ("`r  {0} waiting..." -f $spin[$n++ % 4]) -NoNewline -ForegroundColor DarkGray
            $drawn = $true
        }

        if ($action.status -in @('Succeeded', 'Failed', 'TimeOut', 'Cancelled')) {
            if ($drawn) { Write-Host '' }
            Write-Transcript @{ event = 'complete'; actionId = $ActionId; status = $action.status }
            return $action
        }
        Start-Sleep -Seconds $PollIntervalSeconds
    }

    if ($drawn) { Write-Host '' }
    Write-Status "Timed out locally after $ActionTimeoutMinutes min. The action may still complete server-side: 'actions' to check." 'Warn'
    $null
}

function Show-ActionResult {
    <# Pulls each command's result. PutFile produces none. #>
    # Not Mandatory: the callers legitimately pass $null when an action was never
    # created or never became visible, and Mandatory refuses to bind $null.
    param($Action)

    if (-not $Action -or $Action.status -ne 'Succeeded') { $script:FailedActions++ }

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

    # The payload is endpoint-supplied and may be malware. Use an unguessable name in the
    # shared temp dir, and remove it even when a step below fails.
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('lr_{0}.bin' -f [guid]::NewGuid().ToString('N'))
    try {
        Invoke-WebRequest -Uri $Url -OutFile $tmp -MaximumRedirection 5 | Out-Null

        # Only the header is needed here. ReadAllBytes refuses files over 2 GB, and GetFile
        # results can be larger.
        $head = [byte[]]::new(64KB)
        $hs = [IO.File]::OpenRead($tmp)
        try { $headLength = $hs.Read($head, 0, $head.Length) } finally { $hs.Dispose() }
        [Array]::Resize([ref]$head, $headLength)
        $isGzip = $head.Length -gt 2 -and $head[0] -eq 0x1f -and $head[1] -eq 0x8b

        if ($CommandType -eq 'GetFile') {
            if (-not (Test-Path $DownloadPath)) { New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null }
            $stem = '{0}_{1}_{2}' -f (ConvertTo-SafeFileName $script:Machine.computerDnsName), $ActionId.Substring(0, 8), $Index
            # Hash the download as received too, since the saved file is usually ungzipped.
            $rawSha256 = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLower()
            $rawLength = (Get-Item -LiteralPath $tmp).Length
            $extracted = $false
            if ($isGzip) {
                $orig = Get-GzipOriginalName -Bytes $head
                $orig = ConvertTo-SafeFileName $orig
                $leaf = if ($orig) { '{0}_{1}' -f $stem, $orig } else { $stem }
                $out = Join-Path $DownloadPath $leaf
                $in = $gz = $fs = $null
                try {
                    $in = [IO.File]::OpenRead($tmp)
                    $gz = [IO.Compression.GZipStream]::new($in, [IO.Compression.CompressionMode]::Decompress)
                    $fs = [IO.File]::Create($out)
                    $extracted = Copy-StreamBounded -From $gz -To $fs -Limit ([long]$MaxExtractGB * 1GB)
                } finally {
                    foreach ($s in $fs, $gz, $in) { if ($s) { $s.Dispose() } }
                }
                if ($extracted) {
                    Write-Status "  collected -> $out ($([math]::Round([IO.FileInfo]::new($out).Length/1KB,1)) KB, ungzipped)" 'Good'
                } else {
                    [IO.File]::Delete($out)
                    $out = "$out.gz"
                    Copy-Item -LiteralPath $tmp $out -Force
                    Write-Status "  ungzipped size exceeds -MaxExtractGB $MaxExtractGB; kept as received -> $out" 'Warn'
                }
            } else {
                $out = Join-Path $DownloadPath "$stem.bin"
                Copy-Item -LiteralPath $tmp $out -Force
                Write-Status "  collected -> $out" 'Good'
            }

            # Hash what was written to disk so the transcript can stand as evidence that the
            # file examined later is the file that was collected. Sizes come from .NET rather
            # than Get-Item, which on Linux fails to find a name starting with '..' (a
            # sanitized device name can).
            $sha256 = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLower()
            $length = [IO.FileInfo]::new($out).Length
            Write-Status "  sha256 $sha256" 'Dim'
            if ($extracted) { Write-Status "  sha256 $rawSha256 (as received)" 'Dim' }
            Write-Transcript @{
                event = 'getfile'; actionId = $ActionId; index = $Index; savedTo = $out; sha256 = $sha256; bytes = $length
                rawSha256 = $rawSha256; rawBytes = $rawLength; ungzipped = $extracted
            }
            return
        }

        # RunScript: result is text (usually JSON with script_output / script_errors)
        $text = if ($isGzip) {
            $in = $gz = $sr = $null
            try {
                $in = [IO.File]::OpenRead($tmp)
                $gz = [IO.Compression.GZipStream]::new($in, [IO.Compression.CompressionMode]::Decompress)
                $sr = [IO.StreamReader]::new($gz)
                $sr.ReadToEnd()
            } finally {
                foreach ($s in $sr, $gz, $in) { if ($s) { $s.Dispose() } }
            }
        } else {
            [IO.File]::ReadAllText($tmp)
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }

    $entry = @{ event = 'runscript_result'; actionId = $ActionId; index = $Index; bytes = $text.Length }
    if ($SaveOutput) {
        # Saved as received: the file is evidence, and nothing renders it to a terminal here.
        if (-not (Test-Path $DownloadPath)) { New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null }
        $out = Join-Path $DownloadPath ('{0}_{1}_{2}_output.txt' -f
            (ConvertTo-SafeFileName $script:Machine.computerDnsName), $ActionId.Substring(0, 8), $Index)
        [IO.File]::WriteAllText($out, $text)
        $entry.savedTo = $out
        $entry.sha256 = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLower()
    }

    # Remove terminal escape sequences before they reach the console, the 'last' cache, or the transcript.
    $text = Remove-ControlCharacter $text

    # Keep what was shown, not the raw JSON envelope, so 'last' reprints the same view.
    $shown = [System.Collections.Generic.List[string]]::new()
    try {
        $json = $text | ConvertFrom-Json
        foreach ($field in 'script_output', 'output', 'script_errors', 'errors', 'exit_code') {
            if ($json.PSObject.Properties.Name -contains $field) {
                # Sanitize decoded JSON string
                $val = Remove-ControlCharacter "$($json.$field)"
                if ($null -ne $val -and "$val".Trim()) {
                    $lvl = if ($field -match 'error') { 'Bad' } else { 'Dim' }
                    if ($field -match 'output') {
                        Write-Host $val
                        $shown.Add($val)
                    } else {
                        $line = '  {0}: {1}' -f $field, $val
                        Write-Status $line $lvl
                        $shown.Add($line)
                    }
                }
            }
        }
    } catch {
        Write-Verbose 'RunScript result is not JSON; printing raw text.'
    }

    if ($shown.Count -eq 0) {
        Write-Host $text
        $shown.Add($text)
    }
    $script:LastResult = $shown -join [Environment]::NewLine
    if ($entry.savedTo) { Write-Status "  saved -> $($entry.savedTo)" 'Dim' }
    Write-Transcript $entry
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
                                  (both ask before changing an existing file; --force skips)

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

function Build-ChainedCommand {
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

function Write-Usage {
    <# A warning at the prompt, but an error under -Command so a typo in a batch fails
       the run instead of exiting 0. #>
    param([string]$Message)
    if ($script:NonInteractive) { throw $Message }
    Write-Status $Message 'Warn'
}

function Confirm-Action {
    <# Asks y/N at the prompt. Under -Command there is nobody to ask, so the line must
       carry --force instead. #>
    param([string]$Prompt, [switch]$Force)
    if ($Force) { return $true }
    if ($script:NonInteractive) { throw "$Prompt Add --force to confirm under -Command." }
    (Read-Host "$Prompt [y/N]") -match '^\s*y(es)?\s*$'
}

function Invoke-ConsoleLine {
    <# Executes one console line, interactive or not. Returns $false when the session
       should end (exit/quit), $true otherwise. Errors propagate to the caller, which
       decides whether to log-and-continue (REPL) or fail the run (-Command). Cases that
       produce pipeline output go through Out-Host so the return value stays a clean bool. #>
    param([string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return $true }

    $tokens = @(Split-CommandLine $Line)
    $verb = ([string]$tokens[0]).ToLower()
    # Arguments after the verb, already unquoted. Use these rather than re-splitting
    # $rest, which would break a quoted "path with spaces" apart again.
    $parts = @($tokens | Select-Object -Skip 1)
    $rest = $parts -join ' '
    # The tokenizer strips quotes. Verbs that forward free text to the endpoint need
    # the line exactly as typed.
    $rawRest = if ($Line -match '^\s*\S+\s+(.+)$') { $Matches[1].Trim() } else { '' }

    switch ($verb) {
        { $_ -in 'exit', 'quit' } {
            Write-Status 'Closing local session. Queued actions continue server-side.' 'Dim'
            return $false
        }
        'help' { Show-Help | Out-Host; break }

        'machine' {
            $script:Machine | Select-Object computerDnsName, id, osPlatform, version, healthStatus,
                riskScore, exposureLevel, lastIpAddress, lastExternalIpAddress, lastSeen, rbacGroupName |
                Format-List | Out-Host
            break
        }

        'open' {
            if (-not $rest) { Write-Usage 'Usage: open <deviceName|machineId>'; break }
            $script:Machine = if ($rest -match '^(?i)[0-9a-f]{40}$') {
                Resolve-MdeMachine -Id $rest
            } else {
                Resolve-MdeMachine -Name $rest
            }
            Write-Transcript @{ event = 'retarget'; machine = $script:Machine.computerDnsName; machineId = $script:Machine.id }
            Write-Status "Now targeting $($script:Machine.computerDnsName)" 'Good'
            break
        }

        'comment' {
            if ($rawRest) { $script:SessionComment = $rawRest; Write-Status "Comment set." 'Good' }
            else { Write-Host $script:SessionComment }
            break
        }

        'result' {
            # Re-fetch a past action's output. Useful after a permissions fix, or
            # when the local session dropped while the action kept running.
            if (-not $parts) { Write-Usage 'Usage: result <actionId> [index]'; break }
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
            break
        }

        'last' {
            if ($script:LastResult) { Write-Host $script:LastResult } else { Write-Status 'No result cached.' 'Warn' }
            break
        }

        'actions' {
            $take = if ($rest -match '^\d+$') { [int]$rest } else { 10 }
            $filter = [uri]::EscapeDataString("machineId eq '$($script:Machine.id)'")
            # The list API documents $filter and $top but not $orderby, so the
            # server's ordering is not guaranteed. Over-fetch and sort locally.
            $fetch = [Math]::Max(100, $take)
            @((Invoke-MdeApi -Path "api/machineactions?`$filter=$filter&`$top=$fetch").value) |
                Sort-Object creationDateTimeUtc -Descending |
                Select-Object -First $take |
                Select-Object id, type, status, requestor, creationDateTimeUtc |
                Format-Table -AutoSize | Out-Host
            break
        }

        'cancel' {
            if (-not $parts) { Write-Usage 'Usage: cancel <actionId> [comment]'; break }
            $c = if ($parts.Count -gt 1) { @($parts | Select-Object -Skip 1) -join ' ' } else { 'Cancelled by analyst' }
            Invoke-MdeApi -Method POST -Path "api/machineactions/$($parts[0])/cancel" -Body @{ Comment = $c } | Out-Null
            Write-Transcript @{ event = 'cancel'; actionId = $parts[0]; comment = $c }
            Write-Status 'Cancellation requested.' 'Good'
            break
        }

        'library' {
            $force = $parts -contains '--force'
            $parts = @($parts | Where-Object { $_ -ne '--force' })
            $sub = if ($parts.Count -gt 0) { ([string]$parts[0]).ToLower() } else { 'list' }
            switch ($sub) {
                'upload' {
                    if ($parts.Count -lt 2) { Write-Usage 'Usage: library upload <path> [description] [--force]'; break }
                    $file = (Resolve-Path -LiteralPath $parts[1]).Path
                    $desc = if ($parts.Count -gt 2) { @($parts | Select-Object -Skip 2) -join ' ' } else { 'Uploaded by Invoke-MdeLiveResponse.ps1' }
                    # The library is tenant-wide, so an overwrite can replace a teammate's script.
                    $leafName = Split-Path $file -Leaf
                    $exists = @((Invoke-MdeApi -Path 'api/libraryfiles').value |
                        Where-Object { $_.fileName -ieq $leafName }).Count -gt 0
                    if ($exists -and -not (Confirm-Action "Library file '$leafName' already exists. Overwrite it for the whole tenant?" -Force:$force)) {
                        Write-Status 'Upload cancelled.' 'Warn'
                        break
                    }
                    # Only scripts take parameters. Binaries staged via 'put' do not,
                    # and advertising parameters on them misleads the portal UI.
                    $isScript = [IO.Path]::GetExtension($file) -in '.ps1', '.psm1'
                    $form = @{
                        file             = Get-Item -LiteralPath $file
                        Description      = $desc
                        HasParameters    = if ($isScript) { 'true' } else { 'false' }
                        OverrideIfExists = if ($exists) { 'true' } else { 'false' }
                    }
                    if ($isScript) { $form.ParametersDescription = 'Passed through the Args parameter' }
                    Invoke-MdeApi -Method POST -Path 'api/libraryfiles' -Form $form | Out-Null
                    # Library files run on every device in the tenant, so record exactly what went up.
                    Write-Transcript @{
                        event = 'library_upload'; fileName = (Split-Path $file -Leaf); source = $file
                        sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
                        bytes = (Get-Item -LiteralPath $file).Length; description = $desc
                    }
                    Write-Status "Uploaded $(Split-Path $file -Leaf) to the tenant library." 'Good'
                }
                'delete' {
                    if ($parts.Count -lt 2) { Write-Usage 'Usage: library delete <fileName> [--force]'; break }
                    if (-not (Confirm-Action "Delete library file '$($parts[1])' for the whole tenant?" -Force:$force)) {
                        Write-Status 'Delete cancelled.' 'Warn'
                        break
                    }
                    $target = [uri]::EscapeDataString($parts[1])
                    Invoke-MdeApi -Method DELETE -Path "api/libraryfiles/$target" | Out-Null
                    Write-Transcript @{ event = 'library_delete'; fileName = $parts[1] }
                    Write-Status "Deleted $($parts[1])." 'Good'
                }
                default {
                    (Invoke-MdeApi -Path 'api/libraryfiles').value |
                        Select-Object fileName, hasParameters, createdBy, lastUpdatedTime, description |
                        Format-Table -AutoSize | Out-Host
                }
            }
            break
        }

        'cmd' {
            if (-not $rawRest) { Write-Usage 'Usage: cmd <powershell expression>'; break }
            # Base64 so quotes, $, ; and dash-prefixed tokens reach the wrapper intact
            # instead of being re-split or bound as its own parameters on the endpoint.
            $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($rawRest))
            Write-Transcript @{ event = 'cmd'; command = $rawRest }
            $commands = @(@{
                type   = 'RunScript'
                params = @(
                    @{ key = 'ScriptName'; value = $CommandWrapperScript },
                    @{ key = 'Args'; value = "-EncodedCommand $encoded" }
                )
            })
            Show-ActionResult (Invoke-LiveResponseAction -Commands $commands -ActionComment $script:SessionComment)
            break
        }

        { $_ -in 'run', 'get', 'put' } {
            # Normalize "run X args --get Y" into the chained form. Use the raw text
            # so quotes survive to Build-ChainedCommand, which needs them to tell a
            # literal "--get" argument from the chain separator.
            $normalized = '--{0} {1}' -f $verb, $rawRest
            $commands = @(Build-ChainedCommand $normalized)
            if (-not $commands) { Write-Usage 'Nothing to submit.'; break }
            Show-ActionResult (Invoke-LiveResponseAction -Commands $commands -ActionComment $script:SessionComment)
            break
        }

        default {
            Write-Usage "Unknown command '$verb'. The API has no shell passthrough -- use 'cmd <powershell>' or 'help'."
        }
    }
    return $true
}

function Write-ConsoleError {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord, [string]$Line)
    Write-Status "! $($ErrorRecord.Exception.Message)" 'Bad'
    Write-Transcript @{ event = 'error'; message = $ErrorRecord.Exception.Message; input = $Line }
}

function Initialize-ConsoleInput {
    <# Best-effort PSReadLine so the REPL gets history, arrow keys and line editing.
       Console commands are kept out of the on-disk PSReadLine history for this session
       (they often name case paths and hosts); the caller's setting is restored on exit. #>
    $script:UsePSReadLine = $false
    $script:PrevHistorySaveStyle = $null
    try {
        Import-Module PSReadLine -ErrorAction Stop
        if (Get-Command PSConsoleHostReadLine -ErrorAction SilentlyContinue) {
            $script:PrevHistorySaveStyle = (Get-PSReadLineOption).HistorySaveStyle
            Set-PSReadLineOption -HistorySaveStyle SaveNothing
            $script:UsePSReadLine = $true
        }
    } catch {
        # Not available (e.g. no console, or a host without PSReadLine): Read-Host is fine.
        Write-Verbose "PSReadLine not used ($($_.Exception.Message)); falling back to Read-Host."
    }
}

function Restore-ConsoleInput {
    if ($null -ne $script:PrevHistorySaveStyle) {
        try { Set-PSReadLineOption -HistorySaveStyle $script:PrevHistorySaveStyle } catch {
            Write-Verbose "Could not restore PSReadLine HistorySaveStyle: $($_.Exception.Message)"
        }
    }
}

function Read-ConsoleLine {
    <# Reads one line. Uses PSReadLine when it initialized cleanly; if it throws at read
       time (redirected input, odd hosts), falls back to Read-Host for the rest of the
       session rather than retrying every line. #>
    param([string]$Prompt)
    Write-Host $Prompt -NoNewline -ForegroundColor Cyan
    if ($script:UsePSReadLine) {
        try {
            return (PSConsoleHostReadLine)
        } catch {
            $script:UsePSReadLine = $false
        }
    }
    Read-Host
}

function Start-Repl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Runs the local prompt loop; the function itself changes no system state.')]
    param()
    Write-Host ''
    Write-Status "Live Response session context established." 'Good'
    Write-Host ("  device : {0}  ({1})" -f $script:Machine.computerDnsName, $script:Machine.osPlatform)
    Write-Host ("  id     : {0}" -f $script:Machine.id)
    Write-Host ("  health : {0}   last seen {1}" -f $script:Machine.healthStatus, $script:Machine.lastSeen)
    Write-Host ("  log    : {0}" -f $script:LogFile) -ForegroundColor DarkGray
    Write-Host '  Type "help" for commands. Each command is a tenant-logged machine action.' -ForegroundColor DarkGray
    Write-Host ''

    Initialize-ConsoleInput
    try {
        while ($true) {
            $line = Read-ConsoleLine -Prompt ('{0}> ' -f $script:Machine.computerDnsName)
            try {
                if (-not (Invoke-ConsoleLine $line)) { return }
            } catch {
                Write-ConsoleError -ErrorRecord $_ -Line $line
            }
        }
    } finally {
        Restore-ConsoleInput
    }
}

function Invoke-CommandBatch {
    <# Non-interactive mode: runs each -Command line in order and returns $true only if
       every line completed without a local error and every submitted action reached
       Succeeded. A failing line does not stop the remaining lines, same as the REPL. #>
    param([string[]]$Lines)

    $ok = $true
    foreach ($line in $Lines) {
        Write-Host ('{0}> {1}' -f $script:Machine.computerDnsName, $line) -ForegroundColor Cyan
        try {
            if (-not (Invoke-ConsoleLine $line)) { break }
        } catch {
            $ok = $false
            Write-ConsoleError -ErrorRecord $_ -Line $line
        }
    }
    $ok -and ($script:FailedActions -eq 0)
}

#endregion

#region Entry point -----------------------------------------------------------

$script:NonInteractive = $Command.Count -gt 0

# Resolve against the PowerShell location now. [IO.File] calls resolve relative paths
# against the process working directory, which Set-Location does not change.
$DownloadPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DownloadPath)
if ($LogPath) { $LogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath) }

if (-not $DeviceName -and -not $MachineId) {
    if ($script:NonInteractive) { throw '-Command requires -DeviceName or -MachineId.' }
    $DeviceName = Read-Host 'Device name (or machine id)'
    if ($DeviceName -match '^(?i)\s*[0-9a-f]{40}\s*$') { $MachineId = $DeviceName.Trim() }
}

$script:AuthMode = $PSCmdlet.ParameterSetName
$script:SessionComment = $Comment
$script:LastResult = $null
$script:RefreshToken = $null
$script:FailedActions = 0
$script:LogFile = if ($LogPath) { $LogPath } else {
    Join-Path (Get-Location) 'lr-sessions' -AdditionalChildPath ('lr-session-{0}.jsonl' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$logDir = Split-Path -Parent $script:LogFile
if ($logDir -and -not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
# Appending to an existing -LogPath continues its chain rather than starting a new one.
$script:TranscriptHash = $null
if (Test-Path -LiteralPath $script:LogFile) {
    $lastLine = Get-Content -LiteralPath $script:LogFile -Tail 1
    if ($lastLine) { $script:TranscriptHash = Get-LineHash $lastLine }
}

Write-Status "Authenticating to $($script:Cfg.Api) ($Cloud)..." 'Info'
Request-Token
Write-Status 'Token acquired.' 'Good'

$script:Machine = if ($MachineId) { Resolve-MdeMachine -Id $MachineId } else { Resolve-MdeMachine -Name $DeviceName }

if ($script:Machine.healthStatus -ne 'Active') {
    Write-Status "Device health is '$($script:Machine.healthStatus)'. Actions will queue until it checks in (up to 3 days)." 'Warn'
}

$mode = if ($script:NonInteractive) { 'command' } else { 'interactive' }
Write-Transcript @{
    event = 'session_start'; machine = $script:Machine.computerDnsName; machineId = $script:Machine.id
    cloud = $Cloud; mode = $mode; tenantId = $TenantId; clientId = $ClientId; authMode = $script:AuthMode
}

$succeeded = $false
$completed = $false
try {
    if ($script:NonInteractive) {
        $succeeded = Invoke-CommandBatch -Lines $Command
    } else {
        Start-Repl
    }
    $completed = $true
} finally {
    # Runs on Ctrl+C and unhandled errors too, so the transcript always has an end.
    $end = @{ event = 'session_end'; completed = $completed }
    if ($script:NonInteractive) { $end.succeeded = [bool]$succeeded }
    Write-Transcript $end
    # The chain cannot show lines cut off the end. Note this hash in the case file to cover that.
    Write-Status "Transcript hash: $script:TranscriptHash" 'Dim'
}

if ($script:NonInteractive) { exit $(if ($succeeded) { 0 } else { 1 }) }

#endregion
