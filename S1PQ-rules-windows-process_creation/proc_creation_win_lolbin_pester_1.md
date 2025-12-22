```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe") and (tgt.process.cmdline contains "Pester" and tgt.process.cmdline contains "Get-Help")) or ((tgt.process.image.path contains "\\cmd.exe" and (tgt.process.cmdline contains "pester" and tgt.process.cmdline contains ";")) and (tgt.process.cmdline contains "help" or tgt.process.cmdline contains "?"))))
```


# Original Sigma Rule:
```yaml
title: Execute Code with Pester.bat
id: 59e938ff-0d6d-4dc3-b13f-36cc28734d4e
status: test
description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
references:
    - https://twitter.com/Oddvarmoe/status/993383596244258816
    - https://github.com/api0cradle/LOLBAS/blob/d148d278f5f205ce67cfaf49afdfb68071c7252a/OSScripts/pester.md
author: Julia Fomina, oscd.community
date: 2020-10-08
modified: 2023-11-09
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense-evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    powershell_module:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Pester'
            - 'Get-Help'
    cmd_execution:
        Image|endswith: '\cmd.exe'
        CommandLine|contains|all:
            - 'pester'
            - ';'
    get_help:
        CommandLine|contains:
            - 'help'
            - '\?'
    condition: powershell_module or (cmd_execution and get_help)
falsepositives:
    - Legitimate use of Pester for writing tests for Powershell scripts and modules
level: medium
```
