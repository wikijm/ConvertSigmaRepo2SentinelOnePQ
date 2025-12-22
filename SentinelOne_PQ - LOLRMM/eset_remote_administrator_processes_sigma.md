```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "era.exe" or src.process.image.path contains "einstaller.exe" or src.process.image.path="*ezhelp*.exe" or src.process.image.path contains "eratool.exe" or src.process.image.path contains "ERAAgent.exe") or (tgt.process.image.path contains "era.exe" or tgt.process.image.path contains "einstaller.exe" or tgt.process.image.path="*ezhelp*.exe" or tgt.process.image.path contains "eratool.exe" or tgt.process.image.path contains "ERAAgent.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ESET Remote Administrator RMM Tool Process Activity
id: 0d8dffd2-87ec-4672-8092-e31f3319c573
status: experimental
description: |
    Detects potential processes activity of ESET Remote Administrator RMM tool
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
            - era.exe
            - einstaller.exe
            - ezhelp*.exe
            - eratool.exe
            - ERAAgent.exe
    selection_image:
        Image|endswith:
            - era.exe
            - einstaller.exe
            - ezhelp*.exe
            - eratool.exe
            - ERAAgent.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ESET Remote Administrator
level: medium
```
