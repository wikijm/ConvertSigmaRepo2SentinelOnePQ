```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*accessserver*.exe" or src.process.image.path contains "accessserver.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Ericom AccessNow RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - accessserver*.exe
    - accessserver.exe
  condition: selection
id: b1f1b872-2e40-4538-acdb-1999ce3e8b1f
status: experimental
description: Detects potential processes activity of Ericom AccessNow RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Ericom AccessNow
level: medium
```
