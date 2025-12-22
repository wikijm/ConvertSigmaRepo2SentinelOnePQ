```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "jumpclient.exe" or src.process.image.path contains "jumpdesktop.exe" or src.process.image.path contains "jumpservice.exe" or src.process.image.path contains "jumpconnect.exe" or src.process.image.path contains "jumpupdater.exe") or (tgt.process.image.path contains "jumpclient.exe" or tgt.process.image.path contains "jumpdesktop.exe" or tgt.process.image.path contains "jumpservice.exe" or tgt.process.image.path contains "jumpconnect.exe" or tgt.process.image.path contains "jumpupdater.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Jump Desktop RMM Tool Process Activity
id: 9acbccef-f6f9-4a81-83ef-38f04540ee4a
status: experimental
description: |
    Detects potential processes activity of Jump Desktop RMM tool
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
            - jumpclient.exe
            - jumpdesktop.exe
            - jumpservice.exe
            - jumpconnect.exe
            - jumpupdater.exe
    selection_image:
        Image|endswith:
            - jumpclient.exe
            - jumpdesktop.exe
            - jumpservice.exe
            - jumpconnect.exe
            - jumpupdater.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Jump Desktop
level: medium
```
