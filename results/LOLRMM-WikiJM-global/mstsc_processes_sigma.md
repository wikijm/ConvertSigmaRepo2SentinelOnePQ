```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\\Windows\\System32\\mstsc.exe" or src.process.image.path contains "Windows\\System32\\mstsc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential mstsc RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\Windows\System32\mstsc.exe
    - '*Windows\System32\mstsc.exe'
  condition: selection
id: 95a522bd-aa12-4d0b-9e44-37381ef561c0
status: experimental
description: Detects potential processes activity of mstsc RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of mstsc
level: medium
```
