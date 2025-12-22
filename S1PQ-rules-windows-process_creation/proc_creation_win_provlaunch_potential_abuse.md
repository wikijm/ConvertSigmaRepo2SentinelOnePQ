```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\provlaunch.exe" and (not ((tgt.process.image.path contains "\\calc.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\notepad.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\wscript.exe") or (tgt.process.image.path contains ":\\PerfLogs\\" or tgt.process.image.path contains ":\\Temp\\" or tgt.process.image.path contains ":\\Users\\Public\\" or tgt.process.image.path contains "\\AppData\\Temp\\" or tgt.process.image.path contains "\\Windows\\System32\\Tasks\\" or tgt.process.image.path contains "\\Windows\\Tasks\\" or tgt.process.image.path contains "\\Windows\\Temp\\")))))
```


# Original Sigma Rule:
```yaml
title: Potential Provlaunch.EXE Binary Proxy Execution Abuse
id: 7f5d1c9a-3e83-48df-95a7-2b98aae6c13c
related:
    - id: f9999590-1f94-4a34-a91e-951e47bedefd # CLI Abuse
      type: similar
    - id: 2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25 # CLI Registry
      type: similar
    - id: 7021255e-5db3-4946-a8b9-0ba7a4644a69 # Registry
      type: similar
status: test
description: Detects child processes of "provlaunch.exe" which might indicate potential abuse to proxy execution.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Provlaunch/
    - https://twitter.com/0gtweet/status/1674399582162153472
author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
date: 2023-08-08
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\provlaunch.exe'
    filter_main_covered_children:
        # Note: this filter is here to avoid duplicate alerting by f9999590-1f94-4a34-a91e-951e47bedefd
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
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
