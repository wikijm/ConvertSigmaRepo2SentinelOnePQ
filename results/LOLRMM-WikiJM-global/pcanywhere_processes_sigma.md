```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "awhost32.exe" or src.process.image.path contains "awrem32.exe" or src.process.image.path contains "pcaquickconnect.exe" or src.process.image.path contains "winaw32.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential pcAnywhere RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - awhost32.exe
    - awrem32.exe
    - pcaquickconnect.exe
    - winaw32.exe
  condition: selection
id: b46a081f-220d-44bc-b6d7-56151c414478
status: experimental
description: Detects potential processes activity of pcAnywhere RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of pcAnywhere
level: medium
```
