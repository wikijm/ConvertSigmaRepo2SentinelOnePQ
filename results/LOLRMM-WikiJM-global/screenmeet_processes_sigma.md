```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ScreenMeetSupport.exe" or src.process.image.path contains "ScreenMeet.Support.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenMeet RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ScreenMeetSupport.exe
    - ScreenMeet.Support.exe
  condition: selection
id: 613fe1d2-7cb9-4de8-9cf4-99eaf7798277
status: experimental
description: Detects potential processes activity of ScreenMeet RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ScreenMeet
level: medium
```
