```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "weezohttpd.exe" or src.process.image.path contains "weezo.exe" or src.process.image.path="*weezo setup*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Weezo RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - weezohttpd.exe
    - weezo.exe
    - weezo setup*.exe
  condition: selection
id: cbcbaca5-c8f9-425e-a44e-f2ab24b474bb
status: experimental
description: Detects potential processes activity of Weezo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Weezo
level: medium
```
