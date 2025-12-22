```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "pcictlui.exe" or src.process.image.path contains "client32.exe" or src.process.image.path contains "pcicfgui.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential NetSupport Manager RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - pcictlui.exe
    - client32.exe
    - pcicfgui.exe
  condition: selection
id: 4205c323-1702-4b84-9d11-a705987a1098
status: experimental
description: Detects potential processes activity of NetSupport Manager RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NetSupport Manager
level: medium
```
