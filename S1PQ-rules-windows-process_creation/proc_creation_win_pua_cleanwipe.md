```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\SepRemovalToolNative_x64.exe" or (tgt.process.image.path contains "\\CATClean.exe" and tgt.process.cmdline contains "--uninstall") or (tgt.process.image.path contains "\\NetInstaller.exe" and tgt.process.cmdline contains "-r") or (tgt.process.image.path contains "\\WFPUnins.exe" and (tgt.process.cmdline contains "/uninstall" and tgt.process.cmdline contains "/enterprise"))))
```


# Original Sigma Rule:
```yaml
title: PUA - CleanWipe Execution
id: f44800ac-38ec-471f-936e-3fa7d9c53100
status: test
description: Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.
references:
    - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/CleanWipe
author: Nasreddine Bencherchali (Nextron Systems)
date: 2021-12-18
modified: 2023-02-14
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\SepRemovalToolNative_x64.exe'
    selection2:
        Image|endswith: '\CATClean.exe'
        CommandLine|contains: '--uninstall'
    selection3:
        Image|endswith: '\NetInstaller.exe'
        CommandLine|contains: '-r'
    selection4:
        Image|endswith: '\WFPUnins.exe'
        CommandLine|contains|all:
            - '/uninstall'
            - '/enterprise'
    condition: 1 of selection*
falsepositives:
    - Legitimate administrative use (Should be investigated either way)
level: high
```
