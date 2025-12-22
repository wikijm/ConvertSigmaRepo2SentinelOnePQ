```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "pcictlui.exe" or src.process.image.path contains "pcicfgui.exe" or src.process.image.path contains "client32.exe") or (tgt.process.image.path contains "pcictlui.exe" or tgt.process.image.path contains "pcicfgui.exe" or tgt.process.image.path contains "client32.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential NetSupport Manager RMM Tool Process Activity
id: 922caa2b-af7d-4657-90f6-45dc003a6151
status: experimental
description: |
    Detects potential processes activity of NetSupport Manager RMM tool
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
            - pcictlui.exe
            - pcicfgui.exe
            - client32.exe
    selection_image:
        Image|endswith:
            - pcictlui.exe
            - pcicfgui.exe
            - client32.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of NetSupport Manager
level: medium
```
