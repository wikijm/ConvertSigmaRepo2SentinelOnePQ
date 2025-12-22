```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "SensoClient.exe" or src.process.image.path contains "SensoService.exe" or src.process.image.path contains "aadg.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Senso.cloud RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - SensoClient.exe
    - SensoService.exe
    - aadg.exe
  condition: selection
id: 5d9ac385-c633-4d68-b713-0b4067fc223e
status: experimental
description: Detects potential processes activity of Senso.cloud RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Senso.cloud
level: medium
```
