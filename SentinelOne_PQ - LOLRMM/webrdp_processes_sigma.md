```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "webrdp.exe" or tgt.process.image.path contains "webrdp.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential WebRDP RMM Tool Process Activity
id: c231e758-93a2-4932-9dc7-dad4c8017bcb
status: experimental
description: |
    Detects potential processes activity of WebRDP RMM tool
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
        ParentImage|endswith: webrdp.exe
    selection_image:
        Image|endswith: webrdp.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of WebRDP
level: medium
```
