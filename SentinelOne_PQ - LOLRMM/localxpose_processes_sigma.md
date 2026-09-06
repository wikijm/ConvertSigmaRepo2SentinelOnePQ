```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\loclx.exe" or tgt.process.image.path contains "\\loclx.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential LocalXpose RMM Tool Process Activity
id: e4a2242d-e715-5aac-9b0c-4fea9cc8f93f
status: experimental
description: |
    Detects potential processes activity of LocalXpose RMM tool
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
        ParentImage|endswith: '\\loclx.exe'
    selection_image:
        Image|endswith: '\\loclx.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of LocalXpose
level: medium
```
