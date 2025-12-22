```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "pstlaunch.exe" or src.process.image.path contains "ptdskclient.exe" or src.process.image.path contains "ptdskhost.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential TeleDesktop RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - pstlaunch.exe
    - ptdskclient.exe
    - ptdskhost.exe
  condition: selection
id: 43f2f2b7-a006-4ed3-814a-e16eceb94cf6
status: experimental
description: Detects potential processes activity of TeleDesktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TeleDesktop
level: medium
```
