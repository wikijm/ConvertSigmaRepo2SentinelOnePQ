```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*nateon*.exe" or src.process.image.path contains "nateon.exe" or src.process.image.path contains "nateonmain.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential NoteOn-desktop sharing RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - nateon*.exe
    - nateon.exe
    - nateonmain.exe
  condition: selection
id: cee2070b-07ca-4fec-a1e3-1653fdd6da8a
status: experimental
description: Detects potential processes activity of NoteOn-desktop sharing RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NoteOn-desktop sharing
level: medium
```
