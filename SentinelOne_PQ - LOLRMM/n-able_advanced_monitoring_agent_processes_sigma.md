```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*Agent_*_RW.exe" or src.process.image.path contains "BASEClient.exe" or src.process.image.path contains "BASupApp.exe" or src.process.image.path contains "BASupSrvc.exe" or src.process.image.path contains "BASupSrvcCnfg.exe" or src.process.image.path contains "BASupTSHelper.exe") or (tgt.process.image.path="*Agent_*_RW.exe" or tgt.process.image.path contains "BASEClient.exe" or tgt.process.image.path contains "BASupApp.exe" or tgt.process.image.path contains "BASupSrvc.exe" or tgt.process.image.path contains "BASupSrvcCnfg.exe" or tgt.process.image.path contains "BASupTSHelper.exe")))
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
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - Agent_*_RW.exe
            - BASEClient.exe
            - BASupApp.exe
            - BASupSrvc.exe
            - BASupSrvcCnfg.exe
            - BASupTSHelper.exe
    selection_image:
        Image|endswith:
            - Agent_*_RW.exe
            - BASEClient.exe
            - BASupApp.exe
            - BASupSrvc.exe
            - BASupSrvcCnfg.exe
            - BASupTSHelper.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of N-Able Advanced Monitoring Agent
level: medium
```
