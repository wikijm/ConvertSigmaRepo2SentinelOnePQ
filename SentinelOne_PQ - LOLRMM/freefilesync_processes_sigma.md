```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\FreeFileSync.exe")
```


# Original Sigma Rule:
```yaml
title: Potential FreeFileSync RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\FreeFileSync.exe'
  condition: selection
id: 22878dc1-16ee-4206-a5bf-d28eb818b87e
status: experimental
description: Detects potential processes activity of FreeFileSync RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FreeFileSync
level: medium
```
