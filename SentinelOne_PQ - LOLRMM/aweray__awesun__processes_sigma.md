```sql
// Translated content (automatically translated on 03-05-2025 01:26:06):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*aweray_remote*.exe" or src.process.image.path contains "AweSun.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential AweRay (AweSun) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - aweray_remote*.exe
    - AweSun.exe
  condition: selection
id: e32b8f65-ab9d-4668-a811-d99d471b085d
status: experimental
description: Detects potential processes activity of AweRay (AweSun) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AweRay (AweSun)
level: medium
```
