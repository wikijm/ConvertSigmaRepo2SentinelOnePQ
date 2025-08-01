```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\svchost.exe" and tgt.process.image.path contains "\mmc.exe" and tgt.process.cmdline contains "-Embedding"))
```


# Original Sigma Rule:
```yaml
title: MMC20 Lateral Movement
id: f1f3bf22-deb2-418d-8cce-e1a45e46a5bd
status: test
description: Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe
references:
    - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing
author: '@2xxeformyshirt (Security Risk Advisors) - rule; Teymur Kheirkhabarov (idea)'
date: 2020-03-04
modified: 2021-11-27
tags:
    - attack.execution
    - attack.lateral-movement
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\svchost.exe'
        Image|endswith: '\mmc.exe'
        CommandLine|contains: '-Embedding'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
