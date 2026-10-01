# MDE Live Response: console client

REPL-style client for Microsoft Defender for Endpoint Live Response

[![CI](https://github.com/sshockley/LiveResponseConsole/actions/workflows/ci.yml/badge.svg)](https://github.com/sshockley/LiveResponseConsole/actions/workflows/ci.yml)

## Files

| File | Purpose |
|---|---|
| `Invoke-MdeLiveResponse.ps1` | The client. Auth, device resolution, command loop, result retrieval. |
| `Invoke-LRCommand.ps1` | Library wrapper that backs the `cmd` verb. Upload to the tenant library once. |

## Requirements

- PowerShell 7.2+
- Live Response enabled
- "Live response unsigned script execution" enabled, unless library scripts are signed
- Target device's RBAC group has a remediation level assigned
- Entra app registration, admin-consented, with application permissions:

  | Permission | Needed for |
  |---|---|
  | `Machine.LiveResponse` | everything |
  | `Machine.ReadWrite.All` | resolving device names, `actions` |
  | `Library.Manage` | `library` verbs |

## Creating app registration
See [AppRegistration.md](AppRegistration.md)

## Certificate setup
See [CertificateSetup.md](CertificateSetup.md)

## First run
Add the command script to the library
```powershell
library upload ./Invoke-LRCommand.ps1 "Analyst command channel"
```
`cmd` sends its text base64-encoded (`-EncodedCommand`), so re-upload the wrapper whenever
you update the client. An older wrapper in the library will fail on the encoded argument.

## Authentication

```powershell
# Set up tenant ID and client ID variables
$tid = "<tenant id>"
$cid = "<app id>"
$pfxPwd = Read-Host 'PFX password' -AsSecureString

# Certificate (preferred, no shared secret at rest)
./Invoke-MdeLiveResponse.ps1 -TenantId $tid -ClientId $cid `
    -CertificatePath ./lr-app.pfx -CertificatePassword $pfxPwd -DeviceName ws-eng-042

# Secret from environment
$env:MDE_CLIENT_SECRET = '...'   # or omit and be prompted
./Invoke-MdeLiveResponse.ps1 -TenantId $tid -ClientId $cid -DeviceName ws-eng-042

# Delegated (needs public client flows + delegated permissions, see AppRegistration.md)
./Invoke-MdeLiveResponse.ps1 -TenantId $tid -ClientId $cid -UseDeviceCode -DeviceName ws-eng-042
```
## Parameters

Clouds: `-Cloud Commercial|UsGovGcc|UsGovGccHigh|UsGovDoD`. Override the host with `-ApiBaseUri https://eu.api.security.microsoft.com` for lower latency. Verify gov host names against current docs as they can change.

Other parameters: `-MachineId`, `-DownloadPath`, `-LogPath`, `-PollIntervalSeconds`, `-ActionTimeoutMinutes`, `-MaxExtractGB`, `-SaveOutput`, `-Comment`, `-CommandWrapperScript`, `-Command`.

## Non-interactive mode

Pass `-Command` with one or more commands to run (in order) in one request.

```powershell
./Invoke-MdeLiveResponse.ps1 -TenantId $tid -ClientId $cid -DeviceName ws-eng-042 `
    -CertificatePath ./lr-app.pfx -CertificatePassword $pfxPwd `
    -Command 'comment Case 4711 triage',
             'run Collect-Artifacts.ps1 --get C:\Windows\Temp\out.zip',
             'cmd Get-Process | Sort-Object CPU -Descending | Select-Object -First 10'
```

- Exit code is `0` if every line ran without a local error and every submitted action
  reached `Succeeded`, otherwise `1`. A failing line does not stop the remaining lines.
  Unknown verbs and usage errors count as failures.
- `-DeviceName` or `-MachineId` is required. An ambiguous device name is an error rather
  than a prompt.
- The transcript is written as usual; `session_start` carries `mode: command`.

Read `Invoke-LRCommand.ps1` before uploading. It executes arbitrary strings as SYSTEM on the endpoint. That widens what any holder of `Machine.LiveResponse` can do, compared with a library
of narrow, purpose-built scripts.


## Verbs

```
machine                        target device details
open <name|id>                 retarget
actions [n]                    recent API-initiated actions on this device
cancel <actionId> [comment]    cancel a pending action
comment <text>                 audit comment applied to new actions
last                           reprint last RunScript output
result <actionId> [index]      re-fetch the output of any past action
help | exit

library                        list library files
library upload <path> [desc]
library delete <fileName>

run <ScriptName> [args]        RunScript from library
cmd <powershell>               arbitrary PowerShell via the wrapper
get <remote\path>              collect a file
put <libraryFileName>          stage a file in the device working dir
```

### Chaining

Normally each action/command needs its own session.  You can chain them together to avoid the delay of multiple sessions.

```
run Collect-Artifacts.ps1 --get C:\Windows\Temp\out.zip
put winpmem.exe --run Dump-Memory.ps1 -full --get C:\Windows\Temp\mem.raw.gz
```

## Output

- `RunScript` results print to console; raw text cached for `last`. With `-SaveOutput`
  each result is also saved unsanitized under `-DownloadPath`, with its SHA-256 in the transcript
- `GetFile` results ungzip into `./lr-downloads` (`-DownloadPath`). Anything that would
  ungzip past `-MaxExtractGB` (default 50) is kept as the received `.gz`. The transcript
  records SHA-256 of both the saved file and the download as received
- Session transcript: `./lr-session-<timestamp>.jsonl` (`-LogPath`). Useful as case evidence,
  since tenant-side you otherwise only have the Action center record. It records the tenant,
  app ID and auth mode at session start, and each action's ID and comment when queued

## Limits

| | |
|---|---|
| `runliveresponse` calls | 10/min |
| Concurrent sessions | 25 tenant-wide |
| Per device | one session at a time (`400 ActiveRequestAlreadyExists`) |
| `RunScript` timeout | 10 min, server-side |
| Offline device | action queues up to 3 days |
| Result download link | valid 30 min, regenerable |

429s are retried with `Retry-After`; tokens refresh automatically.

Expect roughly 10 to 40 seconds per command, unlike the sub-second response of the portal console.

## Usage Notes

- Actions started from the portal Device page don't appear in the `machineactions` API, so `actions` shows API-initiated ones only.
- A failed command in a chain aborts everything after it.
- Backslashes in `GetFile` paths are escaped by the script; don't pre-escape them.
- All actions are logged tenant-side and attributed to the app registration, not to you.  Use `comment` to record case context.


## Development

Unit tests cover the network-free parsing and sanitizing helpers (Pester 5). CI runs
PSScriptAnalyzer (failing on Error severity only) and the tests on Windows and Ubuntu.

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -Force
Invoke-Pester -Path ./tests -Output Detailed
Invoke-ScriptAnalyzer -Path . -Recurse
```
