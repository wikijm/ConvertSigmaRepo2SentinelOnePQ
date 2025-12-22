```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "GotoHTTP_x64.exe" or src.process.image.path contains "gotohttp.exe" or src.process.image.path="*GotoHTTP*.exe") or (tgt.process.image.path contains "GotoHTTP_x64.exe" or tgt.process.image.path contains "gotohttp.exe" or tgt.process.image.path="*GotoHTTP*.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential GotoHTTP RMM Tool Process Activity
id: 1cf1f017-5afb-4383-b9ba-dbd94949a8ac
status: experimental
description: |
    Detects potential processes activity of GotoHTTP RMM tool
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
            - GotoHTTP_x64.exe
            - gotohttp.exe
            - GotoHTTP*.exe
    selection_image:
        Image|endswith:
            - GotoHTTP_x64.exe
            - gotohttp.exe
            - GotoHTTP*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of GotoHTTP
level: medium
```
