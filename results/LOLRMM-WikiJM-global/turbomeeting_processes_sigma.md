```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "pcstarter.exe" or src.process.image.path contains "turbomeeting.exe" or src.process.image.path contains "turbomeetingstarter.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential TurboMeeting RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - pcstarter.exe
    - turbomeeting.exe
    - turbomeetingstarter.exe
  condition: selection
id: 65fa645d-2346-4959-b096-ce2c0c8910c2
status: experimental
description: Detects potential processes activity of TurboMeeting RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TurboMeeting
level: medium
```
