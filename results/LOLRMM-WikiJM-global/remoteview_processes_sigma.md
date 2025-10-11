```sql
// Translated content (automatically translated on 11-10-2025 01:20:45):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "remoteview.exe" or src.process.image.path contains "rv.exe" or src.process.image.path contains "rvagent.exe" or src.process.image.path contains "rvagtray.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteView RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - remoteview.exe
    - rv.exe
    - rvagent.exe
    - rvagtray.exe
  condition: selection
id: 6f0bead3-a60a-4f69-934c-72de73a18d10
status: experimental
description: Detects potential processes activity of RemoteView RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemoteView
level: medium
```
