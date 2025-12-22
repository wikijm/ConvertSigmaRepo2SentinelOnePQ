```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "GotoHTTP_x64.exe" or src.process.image.path contains "gotohttp.exe" or src.process.image.path="*GotoHTTP*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential GotoHTTP RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - GotoHTTP_x64.exe
    - gotohttp.exe
    - GotoHTTP*.exe
  condition: selection
id: e2dde6a3-0330-48e1-9b80-73ec40a9201c
status: experimental
description: Detects potential processes activity of GotoHTTP RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GotoHTTP
level: medium
```
