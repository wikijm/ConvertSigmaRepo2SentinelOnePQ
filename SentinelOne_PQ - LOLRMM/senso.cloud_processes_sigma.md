```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "SensoClient.exe" or src.process.image.path contains "SensoService.exe" or src.process.image.path contains "aadg.exe") or (tgt.process.image.path contains "SensoClient.exe" or tgt.process.image.path contains "SensoService.exe" or tgt.process.image.path contains "aadg.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Senso.cloud RMM Tool Process Activity
id: eae4036c-86e7-429d-bd5a-49dc2b2884c7
status: experimental
description: |
    Detects potential processes activity of Senso.cloud RMM tool
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
            - SensoClient.exe
            - SensoService.exe
            - aadg.exe
    selection_image:
        Image|endswith:
            - SensoClient.exe
            - SensoService.exe
            - aadg.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Senso.cloud
level: medium
```
