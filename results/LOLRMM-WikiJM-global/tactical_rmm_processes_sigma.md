```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "tacticalrmm.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Tactical RMM RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - tacticalrmm.exe
  condition: selection
id: 58f7ad72-6d1a-46b6-b998-4a984395f7d5
status: experimental
description: Detects potential processes activity of Tactical RMM RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Tactical RMM
level: medium
```
