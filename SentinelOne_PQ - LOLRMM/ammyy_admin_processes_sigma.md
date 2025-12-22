```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "AMMYY_Admin.exe" or src.process.image.path="*aa_v*.exe" or src.process.image.path contains "AMMYY_Admin.exe" or src.process.image.path contains "AMMYY_Admin.exe") or (tgt.process.image.path contains "AMMYY_Admin.exe" or tgt.process.image.path="*aa_v*.exe" or tgt.process.image.path contains "AMMYY_Admin.exe" or tgt.process.image.path contains "AMMYY_Admin.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Ammyy Admin RMM Tool Process Activity
id: 295131f7-4740-4607-9ce2-551e8c96096d
status: experimental
description: |
    Detects potential processes activity of Ammyy Admin RMM tool
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
            - AMMYY_Admin.exe
            - aa_v*.exe
            - AMMYY_Admin.exe
            - AMMYY_Admin.exe
    selection_image:
        Image|endswith:
            - AMMYY_Admin.exe
            - aa_v*.exe
            - AMMYY_Admin.exe
            - AMMYY_Admin.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Ammyy Admin
level: medium
```
