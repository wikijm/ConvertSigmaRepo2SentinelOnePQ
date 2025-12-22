```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "NTRsupportPro_EN.exe")
```


# Original Sigma Rule:
```yaml
title: Potential NTR Remote RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - NTRsupportPro_EN.exe
  condition: selection
id: 47a5d227-0695-472d-b9c6-b0642522e98e
status: experimental
description: Detects potential processes activity of NTR Remote RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NTR Remote
level: medium
```
