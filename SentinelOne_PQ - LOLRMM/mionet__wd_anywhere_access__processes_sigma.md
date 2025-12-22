```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "mionet.exe" or src.process.image.path contains "mionetmanager.exe") or (tgt.process.image.path contains "mionet.exe" or tgt.process.image.path contains "mionetmanager.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential MioNet (WD Anywhere Access) RMM Tool Process Activity
id: 203d2837-b19e-439f-a7f4-36ec4bbd6a39
status: experimental
description: |
    Detects potential processes activity of MioNet (WD Anywhere Access) RMM tool
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
            - mionet.exe
            - mionetmanager.exe
    selection_image:
        Image|endswith:
            - mionet.exe
            - mionetmanager.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of MioNet (WD Anywhere Access)
level: medium
```
