```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "seetrolcenter.exe" or src.process.image.path contains "seetrolclient.exe" or src.process.image.path contains "seetrolmyservice.exe" or src.process.image.path contains "seetrolremote.exe" or src.process.image.path contains "seetrolsetting.exe") or (tgt.process.image.path contains "seetrolcenter.exe" or tgt.process.image.path contains "seetrolclient.exe" or tgt.process.image.path contains "seetrolmyservice.exe" or tgt.process.image.path contains "seetrolremote.exe" or tgt.process.image.path contains "seetrolsetting.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Seetrol RMM Tool Process Activity
id: 2228b414-a2e0-494e-80f3-5748a36f9188
status: experimental
description: |
    Detects potential processes activity of Seetrol RMM tool
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
            - seetrolcenter.exe
            - seetrolclient.exe
            - seetrolmyservice.exe
            - seetrolremote.exe
            - seetrolsetting.exe
    selection_image:
        Image|endswith:
            - seetrolcenter.exe
            - seetrolclient.exe
            - seetrolmyservice.exe
            - seetrolremote.exe
            - seetrolsetting.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Seetrol
level: medium
```
