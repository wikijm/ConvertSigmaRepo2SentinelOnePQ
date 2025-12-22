```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*SolarWinds-Dameware-DRS*.exe" or src.process.image.path="*DameWare Mini Remote Control*.exe" or src.process.image.path contains "dwrcs.exe" or src.process.image.path contains "\\dwrcst.exe" or src.process.image.path contains "DameWare Remote Support.exe" or src.process.image.path="*SolarWinds-Dameware-MRC*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential DameWare RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - SolarWinds-Dameware-DRS*.exe
    - DameWare Mini Remote Control*.exe
    - dwrcs.exe
    - '*\dwrcst.exe'
    - DameWare Remote Support.exe
    - SolarWinds-Dameware-MRC*.exe
  condition: selection
id: 1d9073a9-6c31-4e3f-9b6d-ea50ad04a5ad
status: experimental
description: Detects potential processes activity of DameWare RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DameWare
level: medium
```
