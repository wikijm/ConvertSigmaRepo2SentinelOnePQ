```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "FixMeit Unattended Access Setup.exe" or src.process.image.path contains "TiExpertStandalone.exe" or src.process.image.path="*FixMeitClient*.exe" or src.process.image.path contains "FixMeit Client.exe" or src.process.image.path contains "FixMeit Expert Setup.exe" or src.process.image.path contains "TiExpertCore.exe" or src.process.image.path contains "fixmeitclient.exe" or src.process.image.path contains "TiClientCore.exe" or src.process.image.path="*TiClientHelper*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential FixMe.it RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - FixMeit Unattended Access Setup.exe
    - TiExpertStandalone.exe
    - FixMeitClient*.exe
    - FixMeit Client.exe
    - FixMeit Expert Setup.exe
    - TiExpertCore.exe
    - fixmeitclient.exe
    - TiClientCore.exe
    - TiClientHelper*.exe
  condition: selection
id: f4cfc99a-3e0c-4f7a-afd8-3f999128a477
status: experimental
description: Detects potential processes activity of FixMe.it RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FixMe.it
level: medium
```
