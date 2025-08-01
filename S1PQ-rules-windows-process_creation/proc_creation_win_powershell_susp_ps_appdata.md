```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "powershell.exe" or tgt.process.cmdline contains "\powershell" or tgt.process.cmdline contains "\pwsh" or tgt.process.cmdline contains "pwsh.exe") and ((tgt.process.cmdline contains "/c " and tgt.process.cmdline contains "\AppData\") and (tgt.process.cmdline contains "Local\" or tgt.process.cmdline contains "Roaming\"))))
```


# Original Sigma Rule:
```yaml
title: PowerShell Script Run in AppData
id: ac175779-025a-4f12-98b0-acdaeb77ea85
status: test
description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
references:
    - https://twitter.com/JohnLaTwC/status/1082851155481288706
    - https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03
author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
date: 2019-01-09
modified: 2022-07-14
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'powershell.exe'
            - '\powershell'
            - '\pwsh'
            - 'pwsh.exe'
    selection2:
        CommandLine|contains|all:
            - '/c '
            - '\AppData\'
        CommandLine|contains:
            - 'Local\'
            - 'Roaming\'
    condition: all of selection*
falsepositives:
    - Administrative scripts
level: medium
```
