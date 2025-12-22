```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "quickassist.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Microsoft Quick Assist RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - quickassist.exe
  condition: selection
id: e9080b05-c0ea-4365-be44-461450421166
status: experimental
description: Detects potential processes activity of Microsoft Quick Assist RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Microsoft Quick Assist
level: medium
```
