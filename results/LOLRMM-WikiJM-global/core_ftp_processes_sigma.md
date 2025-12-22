```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\*\\coreftplite.exe" or src.process.image.path contains "\\coreftplite.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Core FTP RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\*\coreftplite.exe
    - '*\coreftplite.exe'
  condition: selection
id: 394b2510-7844-4a84-be47-3f75ac85bd70
status: experimental
description: Detects potential processes activity of Core FTP RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Core FTP
level: medium
```
