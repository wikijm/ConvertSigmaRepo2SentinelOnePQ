```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "laplink.exe" or src.process.image.path="*laplink-everywhere-setup*.exe" or src.process.image.path contains "laplinkeverywhere.exe" or src.process.image.path contains "llrcservice.exe" or src.process.image.path contains "serverproxyservice.exe" or src.process.image.path contains "OOSysAgent.exe") or (tgt.process.image.path contains "laplink.exe" or tgt.process.image.path="*laplink-everywhere-setup*.exe" or tgt.process.image.path contains "laplinkeverywhere.exe" or tgt.process.image.path contains "llrcservice.exe" or tgt.process.image.path contains "serverproxyservice.exe" or tgt.process.image.path contains "OOSysAgent.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Laplink Everywhere RMM Tool Process Activity
id: 89579976-a789-4554-9ef3-926b38cbb1ed
status: experimental
description: |
    Detects potential processes activity of Laplink Everywhere RMM tool
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
            - laplink.exe
            - laplink-everywhere-setup*.exe
            - laplinkeverywhere.exe
            - llrcservice.exe
            - serverproxyservice.exe
            - OOSysAgent.exe
    selection_image:
        Image|endswith:
            - laplink.exe
            - laplink-everywhere-setup*.exe
            - laplinkeverywhere.exe
            - llrcservice.exe
            - serverproxyservice.exe
            - OOSysAgent.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Laplink Everywhere
level: medium
```
