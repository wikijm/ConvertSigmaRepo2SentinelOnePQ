```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\YandexDisk2.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Yandex.Disk RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\YandexDisk2.exe'
  condition: selection
id: 198f38c5-5460-4c14-9675-f4af8672be6e
status: experimental
description: Detects potential processes activity of Yandex.Disk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Yandex.Disk
level: medium
```
