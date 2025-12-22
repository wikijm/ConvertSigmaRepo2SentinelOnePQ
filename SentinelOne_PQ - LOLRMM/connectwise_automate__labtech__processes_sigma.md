```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "ltsvc.exe" or src.process.image.path contains "ltsvcmon.exe" or src.process.image.path contains "lttray.exe") or (tgt.process.image.path contains "ltsvc.exe" or tgt.process.image.path contains "ltsvcmon.exe" or tgt.process.image.path contains "lttray.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Connectwise Automate (LabTech) RMM Tool Process Activity
id: f8fdfe0f-1508-46b5-91a7-e0a9c3e4407b
status: experimental
description: |
    Detects potential processes activity of Connectwise Automate (LabTech) RMM tool
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
            - ltsvc.exe
            - ltsvcmon.exe
            - lttray.exe
    selection_image:
        Image|endswith:
            - ltsvc.exe
            - ltsvcmon.exe
            - lttray.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Connectwise Automate (LabTech)
level: medium
```
