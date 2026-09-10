```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\Lunixar.exe" or src.process.image.path contains "\\LunixarRemote.exe" or src.process.image.path contains "\\LunixarUpdater.exe") or (tgt.process.image.path contains "\\Lunixar.exe" or tgt.process.image.path contains "\\LunixarRemote.exe" or tgt.process.image.path contains "\\LunixarUpdater.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Lunixar RMM Tool Process Activity
id: db2a7598-e45d-5651-a9af-9fab41d645c4
status: experimental
description: |
    Detects potential processes activity of Lunixar RMM tool
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
            - '\\Lunixar.exe'
            - '\\LunixarRemote.exe'
            - '\\LunixarUpdater.exe'
    selection_image:
        Image|endswith:
            - '\\Lunixar.exe'
            - '\\LunixarRemote.exe'
            - '\\LunixarUpdater.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Lunixar
level: medium
```
