```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "ltsvc.exe" or src.process.image.path contains "ltsvcmon.exe" or src.process.image.path contains "lttray.exe") or (tgt.process.image.path contains "ltsvc.exe" or tgt.process.image.path contains "ltsvcmon.exe" or tgt.process.image.path contains "lttray.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential LabTech RMM (Now ConnectWise Automate) RMM Tool Process Activity
id: 734c8aa4-6b06-4d41-8127-00cc22d63e5e
status: experimental
description: |
    Detects potential processes activity of LabTech RMM (Now ConnectWise Automate) RMM tool
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
    - Legitimate use of LabTech RMM (Now ConnectWise Automate)
level: medium
```
