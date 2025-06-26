```sql
// Translated content (automatically translated on 26-06-2025 00:53:35):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "iit.exe" or src.process.image.path contains "intouch.exe" or src.process.image.path contains "I'm InTouch Go Installer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential I'm InTouch RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - iit.exe
    - intouch.exe
    - I'm InTouch Go Installer.exe
  condition: selection
id: 1f3ab0ec-8988-4e28-964f-53a54c756e4c
status: experimental
description: Detects potential processes activity of I'm InTouch RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of I'm InTouch
level: medium
```
