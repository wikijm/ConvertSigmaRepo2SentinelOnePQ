```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "mygreenpc.exe")
```


# Original Sigma Rule:
```yaml
title: Potential MyGreenPC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - mygreenpc.exe
  condition: selection
id: b31936e6-2ba0-4eaf-9965-ceadb135f6c3
status: experimental
description: Detects potential processes activity of MyGreenPC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MyGreenPC
level: medium
```
