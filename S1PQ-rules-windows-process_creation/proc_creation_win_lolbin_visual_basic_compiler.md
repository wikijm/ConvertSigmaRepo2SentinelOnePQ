```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\vbc.exe" and tgt.process.image.path contains "\cvtres.exe"))
```


# Original Sigma Rule:
```yaml
title: Visual Basic Command Line Compiler Usage
id: 7b10f171-7f04-47c7-9fa2-5be43c76e535
status: test
description: Detects successful code compilation via Visual Basic Command Line Compiler that utilizes Windows Resource to Object Converter.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Vbc/
author: 'Ensar Şamil, @sblmsrsn, @oscd_initiative'
date: 2020-10-07
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.t1027.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\vbc.exe'
        Image|endswith: '\cvtres.exe'
    condition: selection
falsepositives:
    - Utilization of this tool should not be seen in enterprise environment
level: high
```
