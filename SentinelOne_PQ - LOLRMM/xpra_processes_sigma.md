```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "Xpra-Launcher.exe" or src.process.image.path contains "Xpra-x86_64_Setup.exe") or (tgt.process.image.path contains "Xpra-Launcher.exe" or tgt.process.image.path contains "Xpra-x86_64_Setup.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Xpra RMM Tool Process Activity
id: 5f62f298-5f92-4bea-b9e1-dc6b01658142
status: experimental
description: |
    Detects potential processes activity of Xpra RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - Xpra-Launcher.exe
            - Xpra-x86_64_Setup.exe
    selection_image:
        Image|endswith:
            - Xpra-Launcher.exe
            - Xpra-x86_64_Setup.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Xpra
level: medium
```
