```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\cmd.exe" or src.process.image.path contains "\powershell.exe" or src.process.image.path contains "\pwsh.exe") and tgt.process.image.path contains "\explorer.exe" and tgt.process.cmdline contains "explorer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Proxy Execution Via Explorer.EXE From Shell Process
id: 9eb271b9-24ae-4cd4-9465-19cfc1047f3e
status: test
description: |
    Detects the creation of a child "explorer.exe" process from a shell like process such as "cmd.exe" or "powershell.exe".
    Attackers can use "explorer.exe" for evading defense mechanisms by proxying the execution through the latter.
    While this is often a legitimate action, this rule can be use to hunt for anomalies.
    Muddy Waters threat actor was seeing using this technique.
references:
    - https://twitter.com/CyberRaiju/status/1273597319322058752
    - https://app.any.run/tasks/9a8fd563-4c54-4d0a-9ad8-1fe08339cbc3/
author: Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative
date: 2020-10-05
modified: 2024-06-21
tags:
    - attack.defense-evasion
    - attack.t1218
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith: '\explorer.exe'
        CommandLine|contains: 'explorer.exe'
    condition: selection
falsepositives:
    - Legitimate explorer.exe run from a shell host like "cmd.exe" or "powershell.exe"
level: low
```
