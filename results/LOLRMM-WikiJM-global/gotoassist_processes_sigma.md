```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "gotoassist.exe" or src.process.image.path="*g2a*.exe" or src.process.image.path contains "GoTo Assist Opener.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential GoToAssist RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - gotoassist.exe
    - g2a*.exe
    - GoTo Assist Opener.exe
  condition: selection
id: 07ec59df-b06d-40f6-86c0-5b90d94e5b34
status: experimental
description: Detects potential processes activity of GoToAssist RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GoToAssist
level: medium
```
