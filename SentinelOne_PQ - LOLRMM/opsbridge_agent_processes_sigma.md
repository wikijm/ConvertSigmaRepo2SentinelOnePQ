```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\OpsBridgeAgent.exe" or tgt.process.image.path contains "\\OpsBridgeAgent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential OpsBridge Agent RMM Tool Process Activity
id: 2bb1ed93-9053-5c76-9429-4df0272506cf
status: experimental
description: |
    Detects potential processes activity of OpsBridge Agent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-02
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\\OpsBridgeAgent.exe'
    selection_image:
        Image|endswith: '\\OpsBridgeAgent.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of OpsBridge Agent
level: medium
```
