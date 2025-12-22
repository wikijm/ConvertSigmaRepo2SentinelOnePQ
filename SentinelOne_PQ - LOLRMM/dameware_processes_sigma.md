```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*SolarWinds-Dameware-DRS*.exe" or src.process.image.path="*DameWare Mini Remote Control*.exe" or src.process.image.path="*dntus*.exe" or src.process.image.path contains "dwrcs.exe" or src.process.image.path contains "dwrcst.exe" or src.process.image.path contains "DameWare Remote Support.exe" or src.process.image.path="*SolarWinds-Dameware-MRC*.exe") or (tgt.process.image.path="*SolarWinds-Dameware-DRS*.exe" or tgt.process.image.path="*DameWare Mini Remote Control*.exe" or tgt.process.image.path="*dntus*.exe" or tgt.process.image.path contains "dwrcs.exe" or tgt.process.image.path contains "dwrcst.exe" or tgt.process.image.path contains "DameWare Remote Support.exe" or tgt.process.image.path="*SolarWinds-Dameware-MRC*.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential DameWare RMM Tool Process Activity
id: 9c274b89-fa4c-4030-903b-129f013ecee6
status: experimental
description: |
    Detects potential processes activity of DameWare RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - SolarWinds-Dameware-DRS*.exe
            - DameWare Mini Remote Control*.exe
            - dntus*.exe
            - dwrcs.exe
            - dwrcst.exe
            - DameWare Remote Support.exe
            - SolarWinds-Dameware-MRC*.exe
    selection_image:
        Image|endswith:
            - SolarWinds-Dameware-DRS*.exe
            - DameWare Mini Remote Control*.exe
            - dntus*.exe
            - dwrcs.exe
            - dwrcst.exe
            - DameWare Remote Support.exe
            - SolarWinds-Dameware-MRC*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of DameWare
level: medium
```
