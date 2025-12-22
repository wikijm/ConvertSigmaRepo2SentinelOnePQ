```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "remotepass-access.exe" or src.process.image.path contains "rpaccess.exe" or src.process.image.path contains "rpwhostscr.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePass RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - remotepass-access.exe
    - rpaccess.exe
    - rpwhostscr.exe
  condition: selection
id: f525d157-826e-472f-9800-9e5b08d3e430
status: experimental
description: Detects potential processes activity of RemotePass RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemotePass
level: medium
```
