```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*netviewer*.exe" or src.process.image.path contains "netviewer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Netviewer RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - netviewer*.exe
    - netviewer.exe
  condition: selection
id: dcf2f0c3-4771-4020-ac33-97b1558997ff
status: experimental
description: Detects potential processes activity of Netviewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Netviewer
level: medium
```
