```sql
// Translated content (automatically translated on 26-06-2025 00:53:35):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "rpcgrab.exe" or src.process.image.path contains "rpcsetup.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Access Remote PC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rpcgrab.exe
    - rpcsetup.exe
  condition: selection
id: cc09bf82-5dfe-464a-b6e5-14375fe84de5
status: experimental
description: Detects potential processes activity of Access Remote PC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Access Remote PC
level: medium
```
