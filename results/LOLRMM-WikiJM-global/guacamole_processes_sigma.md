```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "guacd.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Guacamole RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - guacd.exe
  condition: selection
id: 12ace335-9d02-4845-bda4-10b1597afc3e
status: experimental
description: Detects potential processes activity of Guacamole RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Guacamole
level: medium
```
