```sql
// Translated content (automatically translated on 20-05-2025 00:53:05):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*dntus*.exe" or src.process.image.path contains "dwrcs.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Dameware-mini remote control Protocol RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - dntus*.exe
    - dwrcs.exe
  condition: selection
id: 37a2b016-e2ab-49f7-933b-1278a701b18f
status: experimental
description: Detects potential processes activity of Dameware-mini remote control
  Protocol RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Dameware-mini remote control Protocol
level: medium
```
