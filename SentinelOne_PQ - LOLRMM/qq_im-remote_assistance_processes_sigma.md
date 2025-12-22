```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "qq.exe" or src.process.image.path contains "QQProtect.exe" or src.process.image.path contains "qqpcmgr.exe") or (tgt.process.image.path contains "qq.exe" or tgt.process.image.path contains "QQProtect.exe" or tgt.process.image.path contains "qqpcmgr.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential QQ IM-remote assistance RMM Tool Process Activity
id: f4d512cf-aa4a-4eaf-a4a2-fa4a037fcb71
status: experimental
description: |
    Detects potential processes activity of QQ IM-remote assistance RMM tool
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
            - qq.exe
            - QQProtect.exe
            - qqpcmgr.exe
    selection_image:
        Image|endswith:
            - qq.exe
            - QQProtect.exe
            - qqpcmgr.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of QQ IM-remote assistance
level: medium
```
