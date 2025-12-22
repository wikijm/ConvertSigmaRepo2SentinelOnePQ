```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\SharPersist.exe" or tgt.process.displayName="SharPersist") or (tgt.process.cmdline contains " -t schtask -c " or tgt.process.cmdline contains " -t startupfolder -c ") or (tgt.process.cmdline contains " -t reg -c " and tgt.process.cmdline contains " -m add") or (tgt.process.cmdline contains " -t service -c " and tgt.process.cmdline contains " -m add") or (tgt.process.cmdline contains " -t schtask -c " and tgt.process.cmdline contains " -m add")))
```


# Original Sigma Rule:
```yaml
title: HackTool - SharPersist Execution
id: 26488ad0-f9fd-4536-876f-52fea846a2e4
status: test
description: Detects the execution of the hacktool SharPersist - used to deploy various different kinds of persistence mechanisms
references:
    - https://www.mandiant.com/resources/blog/sharpersist-windows-persistence-toolkit
    - https://github.com/mandiant/SharPersist
author: Florian Roth (Nextron Systems)
date: 2022-09-15
modified: 2023-02-04
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\SharPersist.exe'
        - Product: 'SharPersist'
    selection_cli_1:
        CommandLine|contains:
            - ' -t schtask -c '
            - ' -t startupfolder -c '
    selection_cli_2:
        CommandLine|contains|all:
            - ' -t reg -c '
            - ' -m add'
    selection_cli_3:
        CommandLine|contains|all:
            - ' -t service -c '
            - ' -m add'
    selection_cli_4:
        CommandLine|contains|all:
            - ' -t schtask -c '
            - ' -m add'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
