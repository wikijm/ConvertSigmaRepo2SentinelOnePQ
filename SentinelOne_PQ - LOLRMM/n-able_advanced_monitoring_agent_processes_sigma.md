```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\BASupSrvc.exe" or src.process.image.path contains "\\winagent.exe" or src.process.image.path contains "\\BASupApp.exe" or src.process.image.path contains "\\BASupTSHelper.exe" or src.process.image.path="*\\Agent_*_RW.exe" or src.process.image.path contains "\\BASEClient.exe" or src.process.image.path contains "\\BASupSrvcCnfg.exe") or (tgt.process.image.path contains "\\BASupSrvc.exe" or tgt.process.image.path contains "\\winagent.exe" or tgt.process.image.path contains "\\BASupApp.exe" or tgt.process.image.path contains "\\BASupTSHelper.exe" or tgt.process.image.path="*\\Agent_*_RW.exe" or tgt.process.image.path contains "\\BASEClient.exe" or tgt.process.image.path contains "\\BASupSrvcCnfg.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential N-Able Advanced Monitoring Agent RMM Tool Process Activity
id: 9528e78f-1698-4561-8344-f45a6086bfc5
status: experimental
description: |
    Detects potential processes activity of N-Able Advanced Monitoring Agent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\BASupSrvc.exe'
            - '\\winagent.exe'
            - '\\BASupApp.exe'
            - '\\BASupTSHelper.exe'
            - '\\Agent_*_RW.exe'
            - '\\BASEClient.exe'
            - '\\BASupSrvcCnfg.exe'
    selection_image:
        Image|endswith:
            - '\\BASupSrvc.exe'
            - '\\winagent.exe'
            - '\\BASupApp.exe'
            - '\\BASupTSHelper.exe'
            - '\\Agent_*_RW.exe'
            - '\\BASEClient.exe'
            - '\\BASupSrvcCnfg.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of N-Able Advanced Monitoring Agent
level: medium
```
