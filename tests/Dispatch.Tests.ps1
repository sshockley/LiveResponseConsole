#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests for Invoke-MdeApi retry handling and Invoke-ConsoleLine dispatch, with the
    network and the action pipeline mocked. Functions are lifted out of the script via
    the AST, as in Console.Tests.ps1.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Stub functions exist only to be mocked.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Read by the lifted functions through dynamic scope.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Test fixture that returns an in-memory object.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '',
    Justification = 'Terse fixture calls.')]
param()

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Invoke-MdeLiveResponse.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors) {
        throw "Parse errors in ${scriptPath}: $($parseErrors | ForEach-Object { $_.Message } | Out-String)"
    }

    foreach ($name in 'Invoke-MdeApi', 'Invoke-ConsoleLine', 'Split-CommandLine', 'Build-ChainedCommand', 'Write-Usage',
        'Request-Token', 'Confirm-Action') {
        $fn = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $false)
        if (-not $fn) { throw "Function $name not found in $scriptPath" }
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    Set-StrictMode -Version 1.0

    # Stand-ins for script functions the code under test calls; mocked per test.
    function Write-Status { param($Message, $Level) }
    function Write-Transcript { param($Entry) }
    function Get-AccessToken { 'token' }
    function Invoke-LiveResponseAction { param($Commands, $ActionComment) }
    function Show-ActionResult { param($Action) }

    function New-Response {
        param([int]$Code, [string]$Content = '', [hashtable]$Headers = @{})
        [pscustomobject]@{ StatusCode = $Code; Content = $Content; Headers = $Headers }
    }

    $script:Cfg = @{ Api = 'https://api.test'; Authority = 'https://login.test'; Resource = 'https://api.test' }
    $CommandWrapperScript = 'Invoke-LRCommand.ps1'
    $TenantId = 'tenant'
    $ClientId = 'client'
}

Describe 'Request-Token (device code)' {
    BeforeEach {
        Mock Start-Sleep {}
        Mock Write-Status {}
        $script:AuthMode = 'DeviceCode'
        $script:RefreshToken = $null
        $script:AccessToken = $null
    }

    It 'keeps the refresh token from a device code sign-in' {
        Mock Invoke-RestMethod -ParameterFilter { $Uri -like '*/devicecode' } {
            [pscustomobject]@{ message = 'go'; device_code = 'dc'; expires_in = 900; interval = 1 }
        }
        Mock Invoke-RestMethod -ParameterFilter { $Uri -like '*/token' } {
            [pscustomobject]@{ access_token = 'at1'; refresh_token = 'rt1'; expires_in = 3600 }
        }
        Request-Token
        $script:AccessToken | Should -Be 'at1'
        $script:RefreshToken | Should -Be 'rt1'
    }

    It 'renews with the refresh token instead of a new device code' {
        $script:RefreshToken = 'rt1'
        Mock Invoke-RestMethod -ParameterFilter { $Uri -like '*/devicecode' } { throw 'should not prompt' }
        Mock Invoke-RestMethod -ParameterFilter { $Uri -like '*/token' -and $Body.grant_type -eq 'refresh_token' } {
            [pscustomobject]@{ access_token = 'at2'; refresh_token = 'rt2'; expires_in = 3600 }
        }
        Request-Token
        $script:AccessToken | Should -Be 'at2'
        $script:RefreshToken | Should -Be 'rt2'
        Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { $Uri -like '*/devicecode' }
    }

    It 'falls back to a new device code when the refresh token is rejected' {
        $script:RefreshToken = 'expired'
        Mock Invoke-RestMethod -ParameterFilter { $Uri -like '*/token' -and $Body.grant_type -eq 'refresh_token' } {
            throw 'invalid_grant'
        }
        Mock Invoke-RestMethod -ParameterFilter { $Uri -like '*/devicecode' } {
            [pscustomobject]@{ message = 'go'; device_code = 'dc'; expires_in = 900; interval = 1 }
        }
        Mock Invoke-RestMethod -ParameterFilter { $Uri -like '*/token' -and $Body.grant_type -like '*device_code' } {
            [pscustomobject]@{ access_token = 'at3'; refresh_token = 'rt3'; expires_in = 3600 }
        }
        Request-Token
        $script:AccessToken | Should -Be 'at3'
        $script:RefreshToken | Should -Be 'rt3'
    }
}

Describe 'Invoke-MdeApi' {
    BeforeEach {
        Mock Start-Sleep {}
        Mock Write-Status {}
        $script:Responses = [System.Collections.Generic.Queue[object]]::new()
        Mock Invoke-WebRequest { $script:Responses.Dequeue() }
    }

    It 'returns parsed JSON on 200' {
        $script:Responses.Enqueue((New-Response -Code 200 -Content '{"id":"a1"}'))
        (Invoke-MdeApi -Path 'api/x').id | Should -Be 'a1'
        Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter { $Uri -eq 'https://api.test/api/x' }
    }

    It 'returns null for an empty success body' {
        $script:Responses.Enqueue((New-Response -Code 204))
        Invoke-MdeApi -Path 'api/x' | Should -BeNullOrEmpty
    }

    It 'waits for Retry-After seconds on 429, then retries' {
        $script:Responses.Enqueue((New-Response 429 '' @{ 'Retry-After' = @('7') }))
        $script:Responses.Enqueue((New-Response 200 '{"ok":true}'))
        (Invoke-MdeApi -Path 'api/x').ok | Should -BeTrue
        Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -eq 7 }
    }

    It 'accepts Retry-After as an HTTP-date' {
        $when = [DateTimeOffset]::UtcNow.AddSeconds(30).ToString('r')
        $script:Responses.Enqueue((New-Response 429 '' @{ 'Retry-After' = @($when) }))
        $script:Responses.Enqueue((New-Response 200 '{}'))
        Invoke-MdeApi -Path 'api/x' | Out-Null
        Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -ge 25 -and $Seconds -le 31 }
    }

    It 'retries a GET on 503' {
        $script:Responses.Enqueue((New-Response 503))
        $script:Responses.Enqueue((New-Response 200 '{"ok":true}'))
        (Invoke-MdeApi -Path 'api/x').ok | Should -BeTrue
    }

    It 'does not retry a POST on 503' {
        $script:Responses.Enqueue((New-Response 503 'unavailable'))
        { Invoke-MdeApi -Method POST -Path 'api/x' -Body @{} } | Should -Throw 'HTTP 503*'
        Should -Invoke Invoke-WebRequest -Times 1
    }

    It 'refreshes the token once on 401' {
        $script:Responses.Enqueue((New-Response 401))
        $script:Responses.Enqueue((New-Response 401))
        { Invoke-MdeApi -Path 'api/x' } | Should -Throw 'HTTP 401*'
        Should -Invoke Invoke-WebRequest -Times 2
    }

    It 'reports the API error code and message' {
        $script:Responses.Enqueue((New-Response 400 '{"error":{"code":"ActiveRequestAlreadyExists","message":"busy"}}'))
        { Invoke-MdeApi -Method POST -Path 'api/x' -Body @{} } |
            Should -Throw 'HTTP 400 on POST https://api.test/api/x -- ActiveRequestAlreadyExists: busy'
    }

    It 'gives up after MaxRetries' {
        1..3 | ForEach-Object { $script:Responses.Enqueue((New-Response 429)) }
        { Invoke-MdeApi -Path 'api/x' -MaxRetries 2 } | Should -Throw 'Gave up after 2 retries*'
    }
}

Describe 'Invoke-ConsoleLine' {
    BeforeEach {
        Mock Write-Status {}
        Mock Show-ActionResult {}
        Mock Invoke-LiveResponseAction { [pscustomobject]@{ id = 'act1'; status = 'Succeeded' } }
        $script:NonInteractive = $false
        $script:SessionComment = 'case 1'
        $script:Machine = [pscustomobject]@{ id = 'm1'; computerDnsName = 'host1' }
    }

    It 'returns false for exit and quit' {
        Invoke-ConsoleLine 'exit' | Should -BeFalse
        Invoke-ConsoleLine 'QUIT' | Should -BeFalse
    }

    It 'returns true for a blank line' {
        Invoke-ConsoleLine '   ' | Should -BeTrue
    }

    It 'sets the session comment from the raw text' {
        Invoke-ConsoleLine 'comment Case "42"  triage' | Out-Null
        $script:SessionComment | Should -Be 'Case "42"  triage'
    }

    It 'sends cmd text base64-encoded through the wrapper' {
        Invoke-ConsoleLine 'cmd Get-ChildItem "C:\Program Files" -Force' | Should -BeTrue
        Should -Invoke Invoke-LiveResponseAction -Times 1 -ParameterFilter {
            $p = $Commands[0].params
            $enc = ($p | Where-Object key -eq 'Args').value -replace '^-EncodedCommand ', ''
            ($p | Where-Object key -eq 'ScriptName').value -eq 'Invoke-LRCommand.ps1' -and
                [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc)) -eq 'Get-ChildItem "C:\Program Files" -Force' -and
                $ActionComment -eq 'case 1'
        }
    }

    It 'chains run and get into one action' {
        Invoke-ConsoleLine 'run Collect.ps1 -full --get C:\out.zip' | Out-Null
        Should -Invoke Invoke-LiveResponseAction -Times 1 -ParameterFilter {
            ($Commands.type -join ',') -eq 'RunScript,GetFile'
        }
    }

    It 'only warns on an unknown verb at the prompt' {
        { Invoke-ConsoleLine 'dir' } | Should -Not -Throw
        Should -Invoke Write-Status -ParameterFilter { $Message -like "Unknown command 'dir'*" -and $Level -eq 'Warn' }
    }

    It 'throws on an unknown verb under -Command' {
        $script:NonInteractive = $true
        { Invoke-ConsoleLine 'dir' } | Should -Throw "Unknown command 'dir'*"
    }

    Context 'library' {
        BeforeEach {
            $script:Upload = Join-Path $TestDrive 'Tool.ps1'
            Set-Content -LiteralPath $script:Upload -Value 'Write-Output 1'
            $script:Existing = @()
            Mock Invoke-MdeApi -ParameterFilter { $Method -ne 'POST' -and $Method -ne 'DELETE' } {
                [pscustomobject]@{ value = @($script:Existing | ForEach-Object { [pscustomobject]@{ fileName = $_ } }) }
            }
            Mock Invoke-MdeApi -ParameterFilter { $Method -in 'POST', 'DELETE' } {}
            Mock Write-Transcript {}
        }

        It 'uploads a new file without asking and without overriding' {
            Mock Read-Host { throw 'should not ask' }
            Invoke-ConsoleLine "library upload `"$script:Upload`"" | Out-Null
            Should -Invoke Invoke-MdeApi -Times 1 -ParameterFilter { $Method -eq 'POST' -and $Form.OverrideIfExists -eq 'false' }
        }

        It 'refuses to overwrite under -Command without --force' {
            $script:NonInteractive = $true
            $script:Existing = @('tool.ps1')
            { Invoke-ConsoleLine "library upload `"$script:Upload`"" } | Should -Throw '*--force*'
            Should -Invoke Invoke-MdeApi -Times 0 -ParameterFilter { $Method -eq 'POST' }
        }

        It 'overwrites with --force' {
            $script:NonInteractive = $true
            $script:Existing = @('Tool.ps1')
            Invoke-ConsoleLine "library upload `"$script:Upload`" new build --force" | Out-Null
            Should -Invoke Invoke-MdeApi -Times 1 -ParameterFilter {
                $Method -eq 'POST' -and $Form.OverrideIfExists -eq 'true' -and $Form.Description -eq 'new build'
            }
        }

        It 'does not delete when the prompt is declined' {
            Mock Read-Host { 'n' }
            Invoke-ConsoleLine 'library delete Tool.ps1' | Out-Null
            Should -Invoke Invoke-MdeApi -Times 0 -ParameterFilter { $Method -eq 'DELETE' }
        }

        It 'deletes when the prompt is accepted' {
            Mock Read-Host { 'y' }
            Invoke-ConsoleLine 'library delete Tool.ps1' | Out-Null
            Should -Invoke Invoke-MdeApi -Times 1 -ParameterFilter { $Method -eq 'DELETE' -and $Path -eq 'api/libraryfiles/Tool.ps1' }
        }
    }

    It 'throws on a usage error under -Command' {
        $script:NonInteractive = $true
        { Invoke-ConsoleLine 'cmd' } | Should -Throw 'Usage: cmd*'
        Should -Invoke Invoke-LiveResponseAction -Times 0
    }
}
