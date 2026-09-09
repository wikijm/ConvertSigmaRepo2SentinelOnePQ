```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\NiniteOne.exe" or src.process.image.path contains "\\NinitePro.exe" or src.process.image.path contains "\\NiniteAgent.exe" or src.process.image.path contains "\\Ninite.exe") or (tgt.process.image.path contains "\\NiniteOne.exe" or tgt.process.image.path contains "\\NinitePro.exe" or tgt.process.image.path contains "\\NiniteAgent.exe" or tgt.process.image.path contains "\\Ninite.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Ninite Pro (Ninite Agent) RMM Tool Process Activity
id: 5dccc833-eb73-5fcc-bb14-7e0d5d894262
status: experimental
description: |
    Detects potential processes activity of Ninite Pro (Ninite Agent) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-07-08
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\NiniteOne.exe'
            - '\\NinitePro.exe'
            - '\\NiniteAgent.exe'
            - '\\Ninite.exe'
    selection_image:
        Image|endswith:
            - '\\NiniteOne.exe'
            - '\\NinitePro.exe'
            - '\\NiniteAgent.exe'
            - '\\Ninite.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Ninite Pro (Ninite Agent)
level: medium
```
