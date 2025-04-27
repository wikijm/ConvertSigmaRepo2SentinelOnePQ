```sql
// Translated content (automatically translated on 27-04-2025 00:53:37):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "nvClient.exe" or src.process.image.path contains "netviewer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Netviewer (GoToMeet) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - nvClient.exe
    - netviewer.exe
  condition: selection
id: dcbbb83f-6aac-41dc-831b-c4a7a9091fa5
status: experimental
description: Detects potential processes activity of Netviewer (GoToMeet) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Netviewer (GoToMeet)
level: medium
```
