```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "putty.exe" or tgt.process.image.path contains "putty.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential PuTTY RMM Tool Process Activity
id: 261c0863-b00c-4413-8339-23372e480275
status: experimental
description: |
    Detects potential processes activity of PuTTY RMM tool
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
        ParentImage|endswith: putty.exe
    selection_image:
        Image|endswith: putty.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of PuTTY
level: medium
```
