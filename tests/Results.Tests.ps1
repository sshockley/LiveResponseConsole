#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests for Receive-LiveResponseResult: GetFile saving, gunzip, the extraction cap,
    hashing, RunScript output handling and temp-file cleanup. The download is mocked.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Stub and mock parameter blocks mirror the real signatures.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Read by the lifted functions through dynamic scope.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Test fixture that returns an in-memory byte array.')]
param()

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Invoke-MdeLiveResponse.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors) {
        throw "Parse errors in ${scriptPath}: $($parseErrors | ForEach-Object { $_.Message } | Out-String)"
    }

    foreach ($name in 'Receive-LiveResponseResult', 'Get-GzipOriginalName', 'Remove-ControlCharacter',
        'ConvertTo-SafeFileName', 'Copy-StreamBounded', 'Open-GzipFile',
        'Get-FileSha256') {
        $fn = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $false)
        if (-not $fn) { throw "Function $name not found in $scriptPath" }
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    Set-StrictMode -Version 1.0

    function Write-Status { param($Message, $Level) }
    function Write-Transcript { param($Entry) }

    function New-GzipPayload {
        # Real gzip data with FNAME set, built by patching the header GZipStream writes.
        param([byte[]]$Data, [string]$FileName)
        $ms = [IO.MemoryStream]::new()
        $gz = [IO.Compression.GZipStream]::new($ms, [IO.Compression.CompressionMode]::Compress)
        $gz.Write($Data, 0, $Data.Length)
        $gz.Dispose()
        $b = [System.Collections.Generic.List[byte]]::new($ms.ToArray())
        $b[3] = 0x08
        $b.InsertRange(10, [byte[]]([Text.Encoding]::ASCII.GetBytes($FileName) + 0))
        , $b.ToArray()
    }

    function Get-Sha256([byte[]]$Bytes) {
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLower()
    }

    $ActionId = 'abcdef0123456789'
}

Describe 'Receive-LiveResponseResult' {
    BeforeEach {
        $DownloadPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $MaxExtractGB = 1
        $SaveOutput = $false
        $script:LastResult = $null
        $script:Machine = [pscustomobject]@{ computerDnsName = 'host1.corp'; id = 'm1' }
        $script:Payload = [byte[]]@()
        $script:TempSeen = $null
        Mock Invoke-WebRequest {
            $script:TempSeen = $OutFile
            [IO.File]::WriteAllBytes($OutFile, $script:Payload)
        }
        Mock Write-Transcript {}
        Mock Write-Host {}
    }

    Context 'GetFile' {
        It 'ungzips under the stem plus FNAME and hashes both forms' {
            $data = [Text.Encoding]::UTF8.GetBytes('hello world')
            $script:Payload = New-GzipPayload -Data $data -FileName 'C:\Windows\Temp\out.txt'
            Receive-LiveResponseResult -Url 'u' -CommandType GetFile -ActionId $ActionId -Index 0

            $out = Join-Path $DownloadPath 'host1.corp_abcdef01_0_out.txt'
            [IO.File]::ReadAllBytes($out) | Should -Be $data
            Should -Invoke Write-Transcript -Times 1 -ParameterFilter {
                $Entry.event -eq 'getfile' -and $Entry.savedTo -eq $out -and $Entry.ungzipped -and
                    $Entry.sha256 -eq (Get-Sha256 $data) -and $Entry.rawSha256 -eq (Get-Sha256 $script:Payload)
            }
        }

        It 'keeps the gzip as received when it would exceed -MaxExtractGB' {
            Mock Copy-StreamBounded { $false }
            $script:Payload = New-GzipPayload -Data ([byte[]](1..50)) -FileName 'big.raw'
            Receive-LiveResponseResult -Url 'u' -CommandType GetFile -ActionId $ActionId -Index 1

            $out = Join-Path $DownloadPath 'host1.corp_abcdef01_1_big.raw.gz'
            [IO.File]::ReadAllBytes($out) | Should -Be $script:Payload
            Test-Path (Join-Path $DownloadPath 'host1.corp_abcdef01_1_big.raw') | Should -BeFalse
            Should -Invoke Write-Transcript -ParameterFilter { $Entry.event -eq 'getfile' -and -not $Entry.ungzipped }
        }

        It 'saves non-gzip content as .bin unchanged' {
            $script:Payload = [byte[]](1..20)
            Receive-LiveResponseResult -Url 'u' -CommandType GetFile -ActionId $ActionId -Index 2
            [IO.File]::ReadAllBytes((Join-Path $DownloadPath 'host1.corp_abcdef01_2.bin')) | Should -Be $script:Payload
        }

        It 'sanitizes the device name in the file name' {
            $script:Machine.computerDnsName = '..\evil/host'
            $script:Payload = [byte[]](1..20)
            Receive-LiveResponseResult -Url 'u' -CommandType GetFile -ActionId $ActionId -Index 3
            Test-Path -LiteralPath (Join-Path $DownloadPath '.._evil_host_abcdef01_3.bin') | Should -BeTrue
        }

        It 'removes the temp download' {
            $script:Payload = [byte[]](1..20)
            Receive-LiveResponseResult -Url 'u' -CommandType GetFile -ActionId $ActionId -Index 4
            Test-Path -LiteralPath $script:TempSeen | Should -BeFalse
        }
    }

    Context 'RunScript' {
        It 'prints sanitized script_output and caches what was shown for last' {
            $script:Payload = [Text.Encoding]::UTF8.GetBytes('{"script_output":"ok' + [char]0x1b + '[31m","exit_code":0}')
            Receive-LiveResponseResult -Url 'u' -CommandType RunScript -ActionId $ActionId -Index 0
            $r = [string][char]0xFFFD
            $script:LastResult | Should -Be ("ok${r}[31m" + [Environment]::NewLine + '  exit_code: 0')
        }

        It 'falls back to the raw text when the result is not JSON' {
            $script:Payload = [Text.Encoding]::UTF8.GetBytes('plain text')
            Receive-LiveResponseResult -Url 'u' -CommandType RunScript -ActionId $ActionId -Index 0
            $script:LastResult | Should -Be 'plain text'
        }

        It 'reads gzip-compressed output' {
            $script:Payload = New-GzipPayload -Data ([Text.Encoding]::UTF8.GetBytes('{"script_output":"zipped"}')) -FileName 'r.json'
            Receive-LiveResponseResult -Url 'u' -CommandType RunScript -ActionId $ActionId -Index 0
            $script:LastResult | Should -Be 'zipped'
        }

        It 'saves the unsanitized output with -SaveOutput' {
            $SaveOutput = $true
            $raw = '{"script_output":"x' + [char]0x1b + '"}'
            $script:Payload = [Text.Encoding]::UTF8.GetBytes($raw)
            Receive-LiveResponseResult -Url 'u' -CommandType RunScript -ActionId $ActionId -Index 5

            $out = Join-Path $DownloadPath 'host1.corp_abcdef01_5_output.txt'
            [IO.File]::ReadAllText($out) | Should -Be $raw
            Should -Invoke Write-Transcript -ParameterFilter {
                $Entry.event -eq 'runscript_result' -and $Entry.savedTo -eq $out -and
                    $Entry.sha256 -eq (Get-Sha256 ([IO.File]::ReadAllBytes($out)))
            }
        }
    }
}
