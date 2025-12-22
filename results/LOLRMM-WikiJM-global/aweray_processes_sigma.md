```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*aweray_remote*.exe" or src.process.image.path contains "AweSun.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential AweRay RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - aweray_remote*.exe
    - AweSun.exe
  condition: selection
id: 33f501f4-fe8e-49bb-a659-5d9a5c852fe5
status: experimental
description: Detects potential processes activity of AweRay RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AweRay
level: medium
```
