#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Unit tests for non-networked parts of Invoke-MdeLiveResponse.ps1.

    The script is not a module and runs authentication at load time, so the functions
    under test are lifted out of it via the AST and dot-sourced individually.
#>

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Invoke-MdeLiveResponse.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors) {
        throw "Parse errors in ${scriptPath}: $($parseErrors | ForEach-Object { $_.Message } | Out-String)"
    }

    foreach ($name in 'Split-CommandLine', 'Build-ChainedCommand', 'Get-GzipOriginalName', 'Remove-ControlCharacter',
        'Copy-StreamBounded', 'Get-LineHash', 'Write-Transcript') {
        $fn = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $false)
        if (-not $fn) { throw "Function $name not found in $scriptPath" }
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    # Match the script's runtime setting
    Set-StrictMode -Version 1.0

    function New-GzipHeader {
        # Builds the leading bytes of a gzip member: ID1 ID2 CM FLG MTIME(4) XFL OS
        # [FNAME NUL] followed by a few filler bytes so the length check passes.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
            Justification = 'Test fixture that returns an in-memory byte array.')]
        param([string]$Name, [switch]$NoName, [switch]$WithExtra)
        $flg = 0
        if (-not $NoName) { $flg = $flg -bor 0x08 }
        if ($WithExtra) { $flg = $flg -bor 0x04 }

        $b = [System.Collections.Generic.List[byte]]::new()
        $b.AddRange([byte[]](0x1f, 0x8b, 0x08, $flg))
        $b.AddRange([byte[]](0x00, 0x00, 0x00, 0x00))   # MTIME
        $b.AddRange([byte[]](0x00, 0x03))               # XFL, OS (Unix)
        if ($WithExtra) {
            $b.AddRange([byte[]](0x02, 0x00, 0xAA, 0xBB)) # XLEN=2, two extra bytes
        }
        if (-not $NoName) {
            $b.AddRange([Text.Encoding]::GetEncoding('ISO-8859-1').GetBytes($Name))
            $b.Add(0)
        }
        $b.AddRange([byte[]](1, 2, 3, 4, 5, 6, 7, 8))   # stand-in for deflate data
        , $b.ToArray()
    }

    function Get-Param {
        param($Command, [string]$Key)
        @($Command.params | Where-Object { $_.key -eq $Key } | ForEach-Object { $_.value })
    }
}

Describe 'Split-CommandLine' {
    It 'splits on whitespace' {
        $t = @(Split-CommandLine 'run Foo.ps1 -a 1')
        $t | Should -Be @('run', 'Foo.ps1', '-a', '1')
    }

    It 'keeps a quoted span as one token and strips the quotes' {
        $t = @(Split-CommandLine 'get "C:\Program Files\x.txt"')
        $t.Count | Should -Be 2
        $t[1] | Should -Be 'C:\Program Files\x.txt'
    }

    It 'preserves internal spacing inside quotes' {
        $t = @(Split-CommandLine 'run Foo.ps1 "a  b"')
        $t[2] | Should -Be 'a  b'
    }

    It 'stays an array for a single token when wrapped in @()' {
        $t = @(Split-CommandLine 'help')
        $t.Count | Should -Be 1
        $t[0] | Should -Be 'help'
    }

    It 'reports Quoted per token with -AsObject' {
        $t = @(Split-CommandLine 'a "b c" d' -AsObject)
        $t.Count | Should -Be 3
        $t.Text | Should -Be @('a', 'b c', 'd')
        $t.Quoted | Should -Be @($false, $true, $false)
    }

    It 'emits an empty-text quoted token for ""' {
        $t = @(Split-CommandLine 'get ""' -AsObject)
        $t.Count | Should -Be 2
        $t[1].Text | Should -Be ''
        $t[1].Quoted | Should -BeTrue
    }
}

Describe 'Build-ChainedCommand' {
    It 'produces a single RunScript for a plain run' {
        $c = @(Build-ChainedCommand '--run Foo.ps1')
        $c.Count | Should -Be 1
        $c[0].type | Should -Be 'RunScript'
        Get-Param $c[0] 'ScriptName' | Should -Be 'Foo.ps1'
        Get-Param $c[0] 'Args' | Should -BeNullOrEmpty
    }

    It 'passes arguments through joined by single spaces' {
        $c = @(Build-ChainedCommand '--run Foo.ps1 -full   -out C:\t')
        Get-Param $c[0] 'Args' | Should -Be '-full -out C:\t'
    }

    It 'orders commands put, run, get regardless of input order' {
        $c = @(Build-ChainedCommand '--get C:\x.zip --run Foo.ps1 --put tool.exe')
        $c.type | Should -Be @('PutFile', 'RunScript', 'GetFile')
        Get-Param $c[0] 'FileName' | Should -Be 'tool.exe'
        Get-Param $c[1] 'ScriptName' | Should -Be 'Foo.ps1'
        Get-Param $c[2] 'Path' | Should -Be 'C:\x.zip'
    }

    It 'treats a quoted "--get" as a script argument, not a separator' {
        $c = @(Build-ChainedCommand '--run Foo.ps1 "--get" plain')
        $c.Count | Should -Be 1
        $c[0].type | Should -Be 'RunScript'
        Get-Param $c[0] 'Args' | Should -Be '"--get" plain'
    }

    It 'still recognizes an unquoted separator after a quoted one' {
        $c = @(Build-ChainedCommand '--run Foo.ps1 "--get" --get C:\real')
        $c.type | Should -Be @('RunScript', 'GetFile')
        Get-Param $c[0] 'Args' | Should -Be '"--get"'
        Get-Param $c[1] 'Path' | Should -Be 'C:\real'
    }

    It 're-quotes quoted arguments and keeps their internal spacing' {
        $c = @(Build-ChainedCommand '--run Foo.ps1 -name "a  b" -x')
        Get-Param $c[0] 'Args' | Should -Be '-name "a  b" -x'
    }

    It 'keeps spaces in a quoted get path' {
        $c = @(Build-ChainedCommand '--get "C:\Program Files\App\log.txt"')
        $c.Count | Should -Be 1
        Get-Param $c[0] 'Path' | Should -Be 'C:\Program Files\App\log.txt'
    }

    It 'throws for an empty --get segment' {
        { Build-ChainedCommand '--run Foo.ps1 --get' } | Should -Throw '--get requires a value.'
    }

    It 'throws for an empty --put segment' {
        { Build-ChainedCommand '--put --run Foo.ps1' } | Should -Throw '--put requires a value.'
    }

    It 'throws for a quoted empty value' {
        { Build-ChainedCommand '--get ""' } | Should -Throw '--get requires a value.'
    }

    It 'throws when run has no script name' {
        { Build-ChainedCommand '--run' } | Should -Throw '--run requires a value.'
    }

    It 'returns nothing when no separator is present' {
        @(Build-ChainedCommand 'Foo.ps1 -a').Count | Should -Be 0
    }
}

Describe 'Get-GzipOriginalName' {
    It 'extracts FNAME from a gzip header' {
        Get-GzipOriginalName -Bytes (New-GzipHeader -Name 'mem.raw') | Should -Be 'mem.raw'
    }

    It 'returns only the leaf of a Windows path' {
        Get-GzipOriginalName -Bytes (New-GzipHeader -Name 'C:\Windows\Temp\out.zip') | Should -Be 'out.zip'
    }

    It 'returns only the leaf of a POSIX path' {
        Get-GzipOriginalName -Bytes (New-GzipHeader -Name '/tmp/case/out.tar') | Should -Be 'out.tar'
    }

    It 'skips an FEXTRA field before FNAME' {
        Get-GzipOriginalName -Bytes (New-GzipHeader -Name 'x.bin' -WithExtra) | Should -Be 'x.bin'
    }

    It 'returns null when FNAME is not present' {
        Get-GzipOriginalName -Bytes (New-GzipHeader -NoName) | Should -BeNullOrEmpty
    }

    It 'returns null for non-gzip input' {
        Get-GzipOriginalName -Bytes ([byte[]](1..20)) | Should -BeNullOrEmpty
    }

    It 'returns null for input too short to hold a header' {
        Get-GzipOriginalName -Bytes ([byte[]](0x1f, 0x8b, 0x08, 0x08)) | Should -BeNullOrEmpty
    }
}

Describe 'Copy-StreamBounded' {
    It 'copies everything and returns true within the limit' {
        $from = [IO.MemoryStream]::new([byte[]](1..10))
        $to = [IO.MemoryStream]::new()
        Copy-StreamBounded -From $from -To $to -Limit 10 | Should -BeTrue
        $to.ToArray() | Should -Be ([byte[]](1..10))
    }

    It 'returns false once the limit is exceeded' {
        $from = [IO.MemoryStream]::new([byte[]](1..10))
        $to = [IO.MemoryStream]::new()
        Copy-StreamBounded -From $from -To $to -Limit 9 | Should -BeFalse
    }
}

Describe 'Transcript hash chain' {
    BeforeAll {
        $script:Verifier = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Test-LRTranscript.ps1'
    }

    BeforeEach {
        $script:LogFile = Join-Path $TestDrive "t-$([guid]::NewGuid()).jsonl"
        $script:TranscriptHash = $null
        Write-Transcript @{ event = 'session_start' }
        Write-Transcript @{ event = 'submit'; commands = @('a') }
        Write-Transcript @{ event = 'session_end' }
    }

    It 'links each line to the hash of the one before' {
        $lines = @(Get-Content -LiteralPath $script:LogFile)
        ($lines[0] | ConvertFrom-Json).prev | Should -BeNullOrEmpty
        ($lines[1] | ConvertFrom-Json).prev | Should -Be (Get-LineHash $lines[0])
        $script:TranscriptHash | Should -Be (Get-LineHash $lines[2])
    }

    It 'verifies an untouched transcript and reports the final hash' {
        $r = & $script:Verifier -Path $script:LogFile
        $r.Valid | Should -BeTrue
        $r.FinalHash | Should -Be $script:TranscriptHash
    }

    It 'reports the line after an edited one' {
        $lines = @(Get-Content -LiteralPath $script:LogFile)
        $lines[1] = $lines[1].Replace('"a"', '"b"')
        Set-Content -LiteralPath $script:LogFile -Value $lines
        $r = & $script:Verifier -Path $script:LogFile
        $r.Valid | Should -BeFalse
        $r.BrokenAtLine | Should -Be 3
    }

    It 'reports a removed line' {
        $lines = @(Get-Content -LiteralPath $script:LogFile)
        Set-Content -LiteralPath $script:LogFile -Value $lines[0], $lines[2]
        (& $script:Verifier -Path $script:LogFile).BrokenAtLine | Should -Be 2
    }
}

Describe 'Remove-ControlCharacter' {
    It 'replaces C0 controls, DEL and C1 controls with U+FFFD' {
        $in = "a`e[31mb`0c" + [char]0x7F + 'd' + [char]0x85 + [char]0x9F + 'e'
        $out = Remove-ControlCharacter $in
        $r = [string][char]0xFFFD
        $out | Should -Be "a${r}[31mb${r}c${r}d${r}${r}e"
    }

    It 'replaces bidi embedding, override and isolate controls' {
        $in = 'a' + [char]0x202E + 'b' + [char]0x2066 + 'c' + [char]0x200F + 'd' + [char]0x061C + 'e'
        $r = [string][char]0xFFFD
        Remove-ControlCharacter $in | Should -Be "a${r}b${r}c${r}d${r}e"
    }

    It 'keeps tab, carriage return and line feed' {
        $in = "col1`tcol2`r`nrow2"
        Remove-ControlCharacter $in | Should -Be $in
    }

    It 'leaves ordinary text untouched' {
        $accented = -join [char[]](0xDC, 0x6E, 0xEF, 0x63, 0xF6, 0x64, 0xE9)   # U-umlaut, n, i-diaeresis, c, o-umlaut, d, e-acute
        $cjk = -join [char[]](0x65E5, 0x672C, 0x8A9E)                          # three CJK ideographs ("Japanese language")
        $in = $accented + ' text with symbols !@#$%^&*() and ' + $cjk
        Remove-ControlCharacter $in | Should -Be $in
    }

    It 'returns an empty string for empty input' {
        Remove-ControlCharacter '' | Should -Be ''
    }
}
