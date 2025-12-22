```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*echoserver*.exe" or tgt.process.image.path="*echoserver*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Echoware RMM Tool Process Activity
id: e03233d4-4bb0-41ed-a5e6-925ef0241a82
status: experimental
description: |
    Detects potential processes activity of Echoware RMM tool
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
        ParentImage|endswith: echoserver*.exe
    selection_image:
        Image|endswith: echoserver*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Echoware
level: medium
```
