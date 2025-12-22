```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*bomgar-scc-*.exe" or src.process.image.path contains "bomgar-scc.exe" or src.process.image.path="*bomgar-pac-*.exe" or src.process.image.path contains "bomgar-pac.exe" or src.process.image.path contains "bomgar-rdp.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential BeyondTrust (Bomgar) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - bomgar-scc-*.exe
    - bomgar-scc.exe
    - bomgar-pac-*.exe
    - bomgar-pac.exe
    - bomgar-rdp.exe
  condition: selection
id: 142b6802-88d2-4dbe-bde2-129487b63509
status: experimental
description: Detects potential processes activity of BeyondTrust (Bomgar) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of BeyondTrust (Bomgar)
level: medium
```
