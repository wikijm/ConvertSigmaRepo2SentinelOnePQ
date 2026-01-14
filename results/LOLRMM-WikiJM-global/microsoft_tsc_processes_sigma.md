```sql
// Translated content (automatically translated on 14-01-2026 01:52:02):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "termsrv.exe" or src.process.image.path contains "mstsc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Microsoft TSC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - termsrv.exe
    - mstsc.exe
  condition: selection
id: 68f5e6b4-717f-4d4f-a633-c99e342469ea
status: experimental
description: Detects potential processes activity of Microsoft TSC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Microsoft TSC
level: medium
```
