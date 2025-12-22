```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*Beinsync*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential BeInSync RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - Beinsync*.exe
  condition: selection
id: 354d1441-64c5-4429-9e43-ae376256f426
status: experimental
description: Detects potential processes activity of BeInSync RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of BeInSync
level: medium
```
