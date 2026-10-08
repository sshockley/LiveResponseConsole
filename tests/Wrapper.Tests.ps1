#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests for Invoke-LRCommand.ps1. The wrapper calls exit, so each case runs it in a
    child pwsh process.
#>
param()

BeforeAll {
    $script:Wrapper = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Invoke-LRCommand.ps1'

    function Invoke-Wrapper {
        param([string[]]$Arguments)
        $out = & pwsh -NoProfile -NonInteractive -File $script:Wrapper @Arguments
        [pscustomobject]@{ Output = $out -join "`n"; ExitCode = $LASTEXITCODE }
    }

    function ConvertTo-Encoded([string]$Text) {
        [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
    }
}

Describe 'Invoke-LRCommand.ps1 protocol check' {
    It 'runs a command at the current protocol' {
        $r = Invoke-Wrapper '-Protocol', '1', '-EncodedCommand', (ConvertTo-Encoded '"a b" + "c"')
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match 'a bc'
    }

    It 'runs a command when no protocol is sent' {
        $r = Invoke-Wrapper '-EncodedCommand', (ConvertTo-Encoded '1 + 1')
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Match '(?m)^2$'
    }

    It 'refuses a newer protocol without running the command' {
        $r = Invoke-Wrapper '-Protocol', '2', '-EncodedCommand', (ConvertTo-Encoded 'Write-Output ran')
        $r.ExitCode | Should -Be 3
        $r.Output | Should -Match 'out of date.*protocol 1.*protocol 2'
        $r.Output | Should -Match 'library upload ./Invoke-LRCommand.ps1 --force'
        $r.Output | Should -Not -Match '(?m)^ran$'
    }
}
