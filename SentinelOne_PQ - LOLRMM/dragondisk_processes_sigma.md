```sql
// Translated content (automatically translated on 21-09-2025 00:53:03):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\DragonDisk.exe")
```


# Original Sigma Rule:
```yaml
title: Potential DragonDisk RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\DragonDisk.exe'
  condition: selection
id: 65c97fea-d785-4b58-99c0-da8135c79f59
status: experimental
description: Detects potential processes activity of DragonDisk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DragonDisk
level: medium
```
