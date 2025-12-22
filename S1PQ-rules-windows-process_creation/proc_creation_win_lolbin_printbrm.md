```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\PrintBrm.exe" and (tgt.process.cmdline contains " -f" and tgt.process.cmdline contains ".zip")))
```


# Original Sigma Rule:
```yaml
title: PrintBrm ZIP Creation of Extraction
id: cafeeba3-01da-4ab4-b6c4-a31b1d9730c7
status: test
description: Detects the execution of the LOLBIN PrintBrm.exe, which can be used to create or extract ZIP files. PrintBrm.exe should not be run on a normal workstation.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/PrintBrm/
author: frack113
date: 2022-05-02
tags:
    - attack.command-and-control
    - attack.t1105
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\PrintBrm.exe'
        CommandLine|contains|all:
            - ' -f'
            - '.zip'
    condition: selection
falsepositives:
    - Unknown
level: high
```
