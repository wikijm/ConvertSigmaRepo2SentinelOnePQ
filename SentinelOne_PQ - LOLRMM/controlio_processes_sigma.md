```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\weCliboardListener.exe" or src.process.image.path contains "\\bbl.exe" or src.process.image.path contains "\\weprtct.exe" or src.process.image.path contains "\\wemonc.exe" or src.process.image.path contains "\\wesvc.exe" or src.process.image.path="*\\wec_launcher_[a-Z0-9]*_.exe" or src.process.image.path contains "\\weInstSvc.exe") or (tgt.process.image.path contains "\\weCliboardListener.exe" or tgt.process.image.path contains "\\bbl.exe" or tgt.process.image.path contains "\\weprtct.exe" or tgt.process.image.path contains "\\wemonc.exe" or tgt.process.image.path contains "\\wesvc.exe" or tgt.process.image.path="*\\wec_launcher_[a-Z0-9]*_.exe" or tgt.process.image.path contains "\\weInstSvc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Controlio RMM Tool Process Activity
id: 04ef9824-7467-570b-a519-eb537b7ae102
status: experimental
description: |
    Detects potential processes activity of Controlio RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - '\\weCliboardListener.exe'
            - '\\bbl.exe'
            - '\\weprtct.exe'
            - '\\wemonc.exe'
            - '\\wesvc.exe'
            - '\\wec_launcher_[a-Z0-9]*_.exe'
            - '\\weInstSvc.exe'
    selection_image:
        Image|endswith:
            - '\\weCliboardListener.exe'
            - '\\bbl.exe'
            - '\\weprtct.exe'
            - '\\wemonc.exe'
            - '\\wesvc.exe'
            - '\\wec_launcher_[a-Z0-9]*_.exe'
            - '\\weInstSvc.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Controlio
level: medium
```
