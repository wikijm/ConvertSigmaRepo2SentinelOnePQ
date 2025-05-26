```sql
// Translated content (automatically translated on 26-05-2025 01:41:37):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "TeamTaskManager.exe" or src.process.image.path contains "DSGuest.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential DeskShare RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - TeamTaskManager.exe
    - DSGuest.exe
  condition: selection
id: 7bf7edf6-bcbe-4916-b9f0-139d63834ac3
status: experimental
description: Detects potential processes activity of DeskShare RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DeskShare
level: medium
```
