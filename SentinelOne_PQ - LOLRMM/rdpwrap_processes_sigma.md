```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "RDPWInst.exe" or src.process.image.path contains "RDPCheck.exe" or src.process.image.path contains "RDPConf.exe") or (tgt.process.image.path contains "RDPWInst.exe" or tgt.process.image.path contains "RDPCheck.exe" or tgt.process.image.path contains "RDPConf.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential rdpwrap RMM Tool Process Activity
id: e193726e-dd20-4e5a-ac47-79169375390c
status: experimental
description: |
    Detects potential processes activity of rdpwrap RMM tool
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
            - RDPWInst.exe
            - RDPCheck.exe
            - RDPConf.exe
    selection_image:
        Image|endswith:
            - RDPWInst.exe
            - RDPCheck.exe
            - RDPConf.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of rdpwrap
level: medium
```
