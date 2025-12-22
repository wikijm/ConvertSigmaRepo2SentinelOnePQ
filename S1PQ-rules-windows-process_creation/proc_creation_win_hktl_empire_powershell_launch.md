```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " -NoP -sta -NonI -W Hidden -Enc " or tgt.process.cmdline contains " -noP -sta -w 1 -enc " or tgt.process.cmdline contains " -NoP -NonI -W Hidden -enc " or tgt.process.cmdline contains " -noP -sta -w 1 -enc" or tgt.process.cmdline contains " -enc  SQB" or tgt.process.cmdline contains " -nop -exec bypass -EncodedCommand "))
```


# Original Sigma Rule:
```yaml
title: HackTool - Empire PowerShell Launch Parameters
id: 79f4ede3-402e-41c8-bc3e-ebbf5f162581
status: test
description: Detects suspicious powershell command line parameters used in Empire
references:
    - https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
author: Florian Roth (Nextron Systems)
date: 2019-04-20
modified: 2023-02-21
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - ' -NoP -sta -NonI -W Hidden -Enc '
            - ' -noP -sta -w 1 -enc '
            - ' -NoP -NonI -W Hidden -enc '
            - ' -noP -sta -w 1 -enc'
            - ' -enc  SQB'
            - ' -nop -exec bypass -EncodedCommand '
    condition: selection
falsepositives:
    - Other tools that incidentally use the same command line parameters
level: high
```
