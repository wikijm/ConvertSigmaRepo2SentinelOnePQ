```sql
// Translated content (automatically translated on 25-09-2025 01:24:28):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "rfusclient.exe" or src.process.image.path contains "rutserv.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Manipulator System RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rfusclient.exe
    - rutserv.exe
  condition: selection
id: 358291ff-ba8b-4422-858c-7a9e321a527d
status: experimental
description: Detects potential processes activity of Remote Manipulator System RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remote Manipulator System
level: medium
```
