```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\provlaunch.exe" and ((tgt.process.image.path contains "\\calc.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\notepad.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\wscript.exe") or (tgt.process.image.path contains ":\\PerfLogs\\" or tgt.process.image.path contains ":\\Temp\\" or tgt.process.image.path contains ":\\Users\\Public\\" or tgt.process.image.path contains "\\AppData\\Temp\\" or tgt.process.image.path contains "\\Windows\\System32\\Tasks\\" or tgt.process.image.path contains "\\Windows\\Tasks\\" or tgt.process.image.path contains "\\Windows\\Temp\\"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Provlaunch.EXE Child Process
id: f9999590-1f94-4a34-a91e-951e47bedefd
related:
    - id: 7f5d1c9a-3e83-48df-95a7-2b98aae6c13c # CLI Generic
      type: similar
    - id: 2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25 # CLI Registry
      type: similar
    - id: 7021255e-5db3-4946-a8b9-0ba7a4644a69 # Registry
      type: similar
status: test
description: Detects suspicious child processes of "provlaunch.exe" which might indicate potential abuse to proxy execution.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Provlaunch/
    - https://twitter.com/0gtweet/status/1674399582162153472
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-08
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\provlaunch.exe'
    selection_child:
        - Image|endswith:
              - '\calc.exe'
              - '\cmd.exe'
              - '\cscript.exe'
              - '\mshta.exe'
              - '\notepad.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\regsvr32.exe'
              - '\rundll32.exe'
              - '\wscript.exe'
        - Image|contains:
              - ':\PerfLogs\'
              - ':\Temp\'
              - ':\Users\Public\'
              - '\AppData\Temp\'
              - '\Windows\System32\Tasks\'
              - '\Windows\Tasks\'
              - '\Windows\Temp\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
