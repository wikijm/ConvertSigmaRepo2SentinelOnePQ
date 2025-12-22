```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "remoteconsole.exe")
```


# Original Sigma Rule:
```yaml
title: Potential EMCO Remote Console RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - remoteconsole.exe
  condition: selection
id: 03128fb8-63b7-4c37-bebb-ed7f8fcc82ab
status: experimental
description: Detects potential processes activity of EMCO Remote Console RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of EMCO Remote Console
level: medium
```
