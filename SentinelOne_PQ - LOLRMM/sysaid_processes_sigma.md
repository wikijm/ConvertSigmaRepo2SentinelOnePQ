```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "IliAS.exe" or tgt.process.image.path contains "IliAS.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential SysAid RMM Tool Process Activity
id: 0a51c575-0166-498c-9bb2-16918ac45dca
status: experimental
description: |
    Detects potential processes activity of SysAid RMM tool
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
        ParentImage|endswith: IliAS.exe
    selection_image:
        Image|endswith: IliAS.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of SysAid
level: medium
```
