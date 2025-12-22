```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\\Users\*\\ExtraPuTTY-0.30-2016-01-28-installer.exe" or src.process.image.path contains "Users\*\\ExtraPuTTY-0.30-2016-01-28-installer.exe" or src.process.image.path contains "\\ExtraPuTTY-0.30-2016-01-28-installer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ExtraPuTTY RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\Users\*\ExtraPuTTY-0.30-2016-01-28-installer.exe
    - '*Users\*\ExtraPuTTY-0.30-2016-01-28-installer.exe'
    - '*\ExtraPuTTY-0.30-2016-01-28-installer.exe'
  condition: selection
id: 0389408b-eb81-4de9-8304-76da1d845757
status: experimental
description: Detects potential processes activity of ExtraPuTTY RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ExtraPuTTY
level: medium
```
