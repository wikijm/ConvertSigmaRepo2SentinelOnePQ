```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "domotz.exe" or src.process.image.path contains "Domotz Pro Desktop App.exe" or src.process.image.path contains "domotz_bash.exe" or src.process.image.path="*domotz*.exe" or src.process.image.path="*Domotz Pro Desktop App Setup*.exe" or src.process.image.path="*domotz-windows*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Domotz RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - domotz.exe
    - Domotz Pro Desktop App.exe
    - domotz_bash.exe
    - domotz*.exe
    - Domotz Pro Desktop App Setup*.exe
    - domotz-windows*.exe
  condition: selection
id: 5b2ca434-384d-4c09-b980-ec6d63d23eab
status: experimental
description: Detects potential processes activity of Domotz RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Domotz
level: medium
```
