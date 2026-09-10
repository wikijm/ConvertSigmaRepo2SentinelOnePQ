```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\remmon.exe" or tgt.process.image.path contains "\\remmon.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Remmon RMM Tool Process Activity
id: 419832d4-8b4a-5375-9922-ec84b5770418
status: experimental
description: |
    Detects potential processes activity of Remmon RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\\remmon.exe'
    selection_image:
        Image|endswith: '\\remmon.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Remmon
level: medium
```
