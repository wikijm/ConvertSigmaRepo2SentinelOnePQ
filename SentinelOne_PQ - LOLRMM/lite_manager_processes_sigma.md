```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "LMNoIpServer.exe" or tgt.process.image.path contains "LMNoIpServer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Lite Manager RMM Tool Process Activity
id: 782c9f5d-d41d-4064-ab38-01dac19fedba
status: experimental
description: |
    Detects potential processes activity of Lite Manager RMM tool
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
        ParentImage|endswith: LMNoIpServer.exe
    selection_image:
        Image|endswith: LMNoIpServer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Lite Manager
level: medium
```
