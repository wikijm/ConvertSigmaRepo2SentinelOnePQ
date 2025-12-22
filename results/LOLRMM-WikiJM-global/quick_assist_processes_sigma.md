```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "quickassist.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Quick Assist RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - quickassist.exe
  condition: selection
id: b263aa13-5bd2-4540-a32d-f33c21ec545c
status: experimental
description: Detects potential processes activity of Quick Assist RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Quick Assist
level: medium
```
