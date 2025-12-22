```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\wsl.exe" or src.process.image.path contains "\\wslhost.exe") and ((tgt.process.image.path contains "\\calc.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\wscript.exe") or (tgt.process.image.path contains "\\AppData\\Local\\Temp\\" or tgt.process.image.path contains "C:\\Users\\Public\\" or tgt.process.image.path contains "C:\\Windows\\Temp\\" or tgt.process.image.path contains "C:\\Temp\\" or tgt.process.image.path contains "\\Downloads\\" or tgt.process.image.path contains "\\Desktop\\"))))
```


# Original Sigma Rule:
```yaml
title: WSL Child Process Anomaly
id: 2267fe65-0681-42ad-9a6d-46553d3f3480
related:
    - id: dec44ca7-61ad-493c-bfd7-8819c5faa09b # LOLBIN Rule
      type: derived
status: test
description: Detects uncommon or suspicious child processes spawning from a WSL process. This could indicate an attempt to evade parent/child relationship detections or persistence attempts via cron using WSL
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/
    - https://twitter.com/nas_bench/status/1535431474429808642
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-23
modified: 2023-08-15
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\wsl.exe'
            - '\wslhost.exe'
    selection_children_images:
        Image|endswith:
            # Add more suspicious/uncommon "lolbin" processes
            - '\calc.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\wscript.exe'
    selection_children_paths:
        Image|contains:
            - '\AppData\Local\Temp\'
            - 'C:\Users\Public\'
            - 'C:\Windows\Temp\'
            - 'C:\Temp\'
            - '\Downloads\'
            - '\Desktop\'
    condition: selection_parent and 1 of selection_children_*
falsepositives:
    - Unknown
level: medium
```
