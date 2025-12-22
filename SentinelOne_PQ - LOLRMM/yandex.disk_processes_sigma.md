```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "YandexDisk2.exe" or tgt.process.image.path contains "YandexDisk2.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Yandex.Disk RMM Tool Process Activity
id: 2a2194fb-fe2e-4905-a4f6-71b953cd8b85
status: experimental
description: |
    Detects potential processes activity of Yandex.Disk RMM tool
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
        ParentImage|endswith: YandexDisk2.exe
    selection_image:
        Image|endswith: YandexDisk2.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Yandex.Disk
level: medium
```
