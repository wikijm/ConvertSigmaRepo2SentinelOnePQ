```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "nhostsvc.exe" or src.process.image.path contains "nhstw32.exe" or src.process.image.path contains "nldrw32.exe" or src.process.image.path contains "rmserverconsolemediator.exe") or (tgt.process.image.path contains "nhostsvc.exe" or tgt.process.image.path contains "nhstw32.exe" or tgt.process.image.path contains "nldrw32.exe" or tgt.process.image.path contains "rmserverconsolemediator.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Netop Remote Control (aka Impero Connect) RMM Tool Process Activity
id: ff29fc42-5515-4c51-9d48-b09fbcfeb22a
status: experimental
description: |
    Detects potential processes activity of Netop Remote Control (aka Impero Connect) RMM tool
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
            - nhostsvc.exe
            - nhstw32.exe
            - nldrw32.exe
            - rmserverconsolemediator.exe
    selection_image:
        Image|endswith:
            - nhostsvc.exe
            - nhstw32.exe
            - nldrw32.exe
            - rmserverconsolemediator.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Netop Remote Control (aka Impero Connect)
level: medium
```
