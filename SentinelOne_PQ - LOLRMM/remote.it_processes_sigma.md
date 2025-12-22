```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "remote-it-installer.exe" or src.process.image.path contains "remote.it.exe" or src.process.image.path contains "remoteit.exe") or (tgt.process.image.path contains "remote-it-installer.exe" or tgt.process.image.path contains "remote.it.exe" or tgt.process.image.path contains "remoteit.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote.it RMM Tool Process Activity
id: cb14cab8-5e1b-4f79-a9ee-51e8bb1cb180
status: experimental
description: |
    Detects potential processes activity of Remote.it RMM tool
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
            - remote-it-installer.exe
            - remote.it.exe
            - remoteit.exe
    selection_image:
        Image|endswith:
            - remote-it-installer.exe
            - remote.it.exe
            - remoteit.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Remote.it
level: medium
```
