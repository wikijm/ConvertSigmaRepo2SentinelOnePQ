```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "clientmrinit.exe" or src.process.image.path contains "mgntsvc.exe" or src.process.image.path contains "routernt.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Sophos-Remote Management System RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - clientmrinit.exe
    - mgntsvc.exe
    - routernt.exe
  condition: selection
id: e01d827a-4e75-484d-bbc5-c5c5179f56a4
status: experimental
description: Detects potential processes activity of Sophos-Remote Management System
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Sophos-Remote Management System
level: medium
```
