```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\xShell.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Xshell RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\xShell.exe'
  condition: selection
id: 95fe2bf1-0c97-4c3c-b42b-c88eb93c1ead
status: experimental
description: Detects potential processes activity of Xshell RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Xshell
level: medium
```
