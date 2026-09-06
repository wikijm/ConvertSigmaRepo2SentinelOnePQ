```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\mstsc.exe" or tgt.process.image.path contains "\\mstsc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential mstsc.exe (Microsoft Remote Desktop Connection) RMM Tool Process Activity
id: 447bc269-37d5-50a4-b474-e60e609c18dd
status: experimental
description: |
    Detects potential processes activity of mstsc.exe (Microsoft Remote Desktop Connection) RMM tool
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
        ParentImage|endswith: '\\mstsc.exe'
    selection_image:
        Image|endswith: '\\mstsc.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of mstsc.exe (Microsoft Remote Desktop Connection)
level: medium
```
