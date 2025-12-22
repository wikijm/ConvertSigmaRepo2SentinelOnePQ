```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "iperius.exe" or src.process.image.path contains "iperiusremote.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Iperius Remote RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - iperius.exe
    - iperiusremote.exe
  condition: selection
id: 971a62f4-b00c-49ac-95fe-b275ca6ce6e0
status: experimental
description: Detects potential processes activity of Iperius Remote RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Iperius Remote
level: medium
```
