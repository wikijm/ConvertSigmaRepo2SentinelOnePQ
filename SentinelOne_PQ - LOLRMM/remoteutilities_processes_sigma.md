```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "rutview.exe" or src.process.image.path contains "rutserv.exe" or src.process.image.path contains "\rutserv.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteUtilities RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rutview.exe
    - rutserv.exe
    - '*\rutserv.exe'
  condition: selection
id: 2f17d129-5b12-40a4-a603-72f0e378057d
status: experimental
description: Detects potential processes activity of RemoteUtilities RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemoteUtilities
level: medium
```
