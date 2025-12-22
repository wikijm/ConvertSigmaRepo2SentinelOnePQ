```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "SecureCRT.EXE" or src.process.image.path contains "SecureCRT.EXE") or (tgt.process.image.path contains "SecureCRT.EXE" or tgt.process.image.path contains "SecureCRT.EXE")))
```


# Original Sigma Rule:
```yaml
title: Potential SecureCRT RMM Tool Process Activity
id: 4931f903-150d-43b3-bed7-1772dbdbd8e3
status: experimental
description: |
    Detects potential processes activity of SecureCRT RMM tool
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
            - SecureCRT.EXE
            - SecureCRT.EXE
    selection_image:
        Image|endswith:
            - SecureCRT.EXE
            - SecureCRT.EXE
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of SecureCRT
level: medium
```
