```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*pocketcloud*.exe" or src.process.image.path contains "pocketcloudservice.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Pocket Cloud (Wyse) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - pocketcloud*.exe
    - pocketcloudservice.exe
  condition: selection
id: 1a280030-c626-468f-b74a-bffacbc724e3
status: experimental
description: Detects potential processes activity of Pocket Cloud (Wyse) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pocket Cloud (Wyse)
level: medium
```
