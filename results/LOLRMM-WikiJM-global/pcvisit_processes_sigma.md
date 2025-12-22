```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "pcvisit.exe" or src.process.image.path contains "pcvisit_client.exe" or src.process.image.path contains "pcvisit-easysupport.exe" or src.process.image.path contains "pcvisit_service_client.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Pcvisit RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - pcvisit.exe
    - pcvisit_client.exe
    - pcvisit-easysupport.exe
    - pcvisit_service_client.exe
  condition: selection
id: da7aef8c-62ce-4abf-adf3-9df130d9dd30
status: experimental
description: Detects potential processes activity of Pcvisit RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pcvisit
level: medium
```
