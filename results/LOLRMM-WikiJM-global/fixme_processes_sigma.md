```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "FixMeit Client.exe" or src.process.image.path contains "TiExpertStandalone.exe" or src.process.image.path="*FixMeitClient*.exe" or src.process.image.path contains "TiExpertCore.exe" or src.process.image.path contains "FixMeit Unattended Access Setup.exe" or src.process.image.path contains "FixMeit Expert Setup.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential FixMe RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - FixMeit Client.exe
    - TiExpertStandalone.exe
    - FixMeitClient*.exe
    - TiExpertCore.exe
    - FixMeit Unattended Access Setup.exe
    - FixMeit Expert Setup.exe
  condition: selection
id: 723d54d9-a8b0-40e4-9b27-a8c97881353f
status: experimental
description: Detects potential processes activity of FixMe RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FixMe
level: medium
```
