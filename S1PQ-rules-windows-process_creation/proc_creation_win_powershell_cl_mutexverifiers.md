```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\powershell.exe" or src.process.image.path contains "\\pwsh.exe") and tgt.process.image.path contains "\\powershell.exe" and tgt.process.cmdline contains " -nologo -windowstyle minimized -file ") and (tgt.process.cmdline contains "\\AppData\\Local\\Temp\\" or tgt.process.cmdline contains "\\Windows\\Temp\\")))
```


# Original Sigma Rule:
```yaml
title: Potential Script Proxy Execution Via CL_Mutexverifiers.ps1
id: 1e0e1a81-e79b-44bc-935b-ddb9c8006b3d
status: test
description: Detects the use of the Microsoft signed script "CL_mutexverifiers" to proxy the execution of additional PowerShell script commands
references:
    - https://lolbas-project.github.io/lolbas/Scripts/CL_mutexverifiers/
author: Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova, frack113
date: 2022-05-21
modified: 2023-08-17
tags:
    - attack.defense-evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection_pwsh:
        ParentImage|endswith:
            # Note: to avoid potential FPs we assume the script was launched from powershell. But in theory it can be launched by any Powershell like process
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith: '\powershell.exe'
        CommandLine|contains: ' -nologo -windowstyle minimized -file '
    selection_temp:
        # Note: Since the function uses "env:temp" the value will change depending on the context of exec
        CommandLine|contains:
            - '\AppData\Local\Temp\'
            - '\Windows\Temp\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
