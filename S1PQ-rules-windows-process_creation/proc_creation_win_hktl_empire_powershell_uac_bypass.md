```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)" or tgt.process.cmdline contains " -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);"))
```


# Original Sigma Rule:
```yaml
title: HackTool - Empire PowerShell UAC Bypass
id: 3268b746-88d8-4cd3-bffc-30077d02c787
status: stable
description: Detects some Empire PowerShell UAC bypass methods
references:
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64
author: Ecco
date: 2019-08-30
modified: 2023-02-21
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
    - car.2019-04-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - ' -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update)'
            - ' -NoP -NonI -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update);'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
