```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ocsinventory.exe" or src.process.image.path contains "ocsservice.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential OCS inventory RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ocsinventory.exe
    - ocsservice.exe
  condition: selection
id: 9da56624-e193-40ca-85a3-831343f5b797
status: experimental
description: Detects potential processes activity of OCS inventory RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of OCS inventory
level: medium
```
