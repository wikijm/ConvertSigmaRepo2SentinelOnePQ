```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "-nop" and tgt.process.cmdline contains " -w " and tgt.process.cmdline contains "hidden" and tgt.process.cmdline contains " -c " and tgt.process.cmdline contains "[Convert]::FromBase64String") or (tgt.process.cmdline contains " -w " and tgt.process.cmdline contains "hidden" and tgt.process.cmdline contains "-noni" and tgt.process.cmdline contains "-nop" and tgt.process.cmdline contains " -c " and tgt.process.cmdline contains "iex" and tgt.process.cmdline contains "New-Object") or (tgt.process.cmdline contains " -w " and tgt.process.cmdline contains "hidden" and tgt.process.cmdline contains "-ep" and tgt.process.cmdline contains "bypass" and tgt.process.cmdline contains "-Enc") or (tgt.process.cmdline contains "powershell" and tgt.process.cmdline contains "reg" and tgt.process.cmdline contains "add" and tgt.process.cmdline contains "\\software\\") or (tgt.process.cmdline contains "bypass" and tgt.process.cmdline contains "-noprofile" and tgt.process.cmdline contains "-windowstyle" and tgt.process.cmdline contains "hidden" and tgt.process.cmdline contains "new-object" and tgt.process.cmdline contains "system.net.webclient" and tgt.process.cmdline contains ".download") or (tgt.process.cmdline contains "iex" and tgt.process.cmdline contains "New-Object" and tgt.process.cmdline contains "Net.WebClient" and tgt.process.cmdline contains ".Download")) and (not (tgt.process.cmdline contains "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1" or tgt.process.cmdline contains "Write-ChocolateyWarning"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious PowerShell Invocations - Specific - ProcessCreation
id: 536e2947-3729-478c-9903-745aaffe60d2
related:
    - id: fce5f582-cc00-41e1-941a-c6fabf0fdb8c
      type: obsolete
    - id: ae7fbf8e-f3cb-49fd-8db4-5f3bed522c71
      type: similar
    - id: 8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090
      type: similar
status: test
description: Detects suspicious PowerShell invocation command parameters
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-05
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_convert_b64:
        CommandLine|contains|all:
            - '-nop'
            - ' -w '
            - 'hidden'
            - ' -c '
            - '[Convert]::FromBase64String'
    selection_iex:
        CommandLine|contains|all:
            - ' -w '
            - 'hidden'
            - '-noni'
            - '-nop'
            - ' -c '
            - 'iex'
            - 'New-Object'
    selection_enc:
        CommandLine|contains|all:
            - ' -w '
            - 'hidden'
            - '-ep'
            - 'bypass'
            - '-Enc'
    selection_reg:
        CommandLine|contains|all:
            - 'powershell'
            - 'reg'
            - 'add'
            - '\software\'
    selection_webclient:
        CommandLine|contains|all:
            - 'bypass'
            - '-noprofile'
            - '-windowstyle'
            - 'hidden'
            - 'new-object'
            - 'system.net.webclient'
            - '.download'
    selection_iex_webclient:
        CommandLine|contains|all:
            - 'iex'
            - 'New-Object'
            - 'Net.WebClient'
            - '.Download'
    filter_chocolatey:
        CommandLine|contains:
            - "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1"
            - 'Write-ChocolateyWarning'
    condition: 1 of selection_* and not 1 of filter_*
falsepositives:
    - Unknown
level: medium
```
