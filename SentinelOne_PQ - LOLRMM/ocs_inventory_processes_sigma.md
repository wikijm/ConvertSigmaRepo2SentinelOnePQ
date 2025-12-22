```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "ocsinventory.exe" or src.process.image.path contains "ocsservice.exe") or (tgt.process.image.path contains "ocsinventory.exe" or tgt.process.image.path contains "ocsservice.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential OCS inventory RMM Tool Process Activity
id: 7751f589-527f-4ada-ad90-ac026b8e6183
status: experimental
description: |
    Detects potential processes activity of OCS inventory RMM tool
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
            - ocsinventory.exe
            - ocsservice.exe
    selection_image:
        Image|endswith:
            - ocsinventory.exe
            - ocsservice.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of OCS inventory
level: medium
```
