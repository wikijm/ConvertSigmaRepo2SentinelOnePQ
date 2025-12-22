```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "ExtraPuTTY-0.30-2016-01-28-installer.exe" or src.process.image.path contains "ExtraPuTTY-0.30-2016-01-28-installer.exe" or src.process.image.path contains "ExtraPuTTY-0.30-2016-01-28-installer.exe") or (tgt.process.image.path contains "ExtraPuTTY-0.30-2016-01-28-installer.exe" or tgt.process.image.path contains "ExtraPuTTY-0.30-2016-01-28-installer.exe" or tgt.process.image.path contains "ExtraPuTTY-0.30-2016-01-28-installer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ExtraPuTTY RMM Tool Process Activity
id: 8b630c38-e054-4ece-b4f9-fd5c36e31300
status: experimental
description: |
    Detects potential processes activity of ExtraPuTTY RMM tool
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
            - ExtraPuTTY-0.30-2016-01-28-installer.exe
            - ExtraPuTTY-0.30-2016-01-28-installer.exe
            - ExtraPuTTY-0.30-2016-01-28-installer.exe
    selection_image:
        Image|endswith:
            - ExtraPuTTY-0.30-2016-01-28-installer.exe
            - ExtraPuTTY-0.30-2016-01-28-installer.exe
            - ExtraPuTTY-0.30-2016-01-28-installer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ExtraPuTTY
level: medium
```
