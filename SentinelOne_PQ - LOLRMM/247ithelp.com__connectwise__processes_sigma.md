```sql
// Translated content (automatically translated on 31-05-2025 00:50:59):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "Remote Workforce Client.exe")
```


# Original Sigma Rule:
```yaml
title: Potential 247ithelp.com (ConnectWise) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - Remote Workforce Client.exe
  condition: selection
id: a2f54c3b-da16-46a2-b437-201b65a53500
status: experimental
description: Detects potential processes activity of 247ithelp.com (ConnectWise) RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of 247ithelp.com (ConnectWise)
level: medium
```
