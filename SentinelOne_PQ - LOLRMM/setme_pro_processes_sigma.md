```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\SetMe_Client.exe" or src.process.image.path contains "\\tinUnattendedModule.exe") or (tgt.process.image.path contains "\\SetMe_Client.exe" or tgt.process.image.path contains "\\tinUnattendedModule.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential SetMe PRO RMM Tool Process Activity
id: b4db7226-1575-5f5f-82bb-93a116b15471
status: experimental
description: |
    Detects potential processes activity of SetMe PRO RMM tool
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
        ParentImage|endswith:
            - '\\SetMe_Client.exe'
            - '\\tinUnattendedModule.exe'
    selection_image:
        Image|endswith:
            - '\\SetMe_Client.exe'
            - '\\tinUnattendedModule.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of SetMe PRO
level: medium
```
