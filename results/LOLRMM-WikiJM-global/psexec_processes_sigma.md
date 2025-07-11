```sql
// Translated content (automatically translated on 11-07-2025 01:45:34):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "psexec.exe" or src.process.image.path contains "psexecsvc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential PSEXEC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - psexec.exe
    - psexecsvc.exe
  condition: selection
id: 11340ea1-ca47-436e-a3ec-658556aa3615
status: experimental
description: Detects potential processes activity of PSEXEC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of PSEXEC
level: medium
```
