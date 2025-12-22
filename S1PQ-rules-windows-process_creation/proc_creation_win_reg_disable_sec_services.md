```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "reg" and tgt.process.cmdline contains "add") and ((tgt.process.cmdline contains "d 4" and tgt.process.cmdline contains "v Start") and (tgt.process.cmdline contains "\\AppIDSvc" or tgt.process.cmdline contains "\\MsMpSvc" or tgt.process.cmdline contains "\\NisSrv" or tgt.process.cmdline contains "\\SecurityHealthService" or tgt.process.cmdline contains "\\Sense" or tgt.process.cmdline contains "\\UsoSvc" or tgt.process.cmdline contains "\\WdBoot" or tgt.process.cmdline contains "\\WdFilter" or tgt.process.cmdline contains "\\WdNisDrv" or tgt.process.cmdline contains "\\WdNisSvc" or tgt.process.cmdline contains "\\WinDefend" or tgt.process.cmdline contains "\\wscsvc" or tgt.process.cmdline contains "\\wuauserv"))))
```


# Original Sigma Rule:
```yaml
title: Security Service Disabled Via Reg.EXE
id: 5e95028c-5229-4214-afae-d653d573d0ec
status: test
description: Detects execution of "reg.exe" to disable security services such as Windows Defender.
references:
    - https://twitter.com/JohnLaTwC/status/1415295021041979392
    - https://github.com/gordonbay/Windows-On-Reins/blob/e587ac7a0407847865926d575e3c46f68cf7c68d/wor.ps1
    - https://vms.drweb.fr/virus/?i=24144899
    - https://bidouillesecurity.com/disable-windows-defender-in-powershell/
author: Florian Roth (Nextron Systems), John Lambert (idea), elhoim
date: 2021-07-14
modified: 2023-06-05
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_reg_add:
        CommandLine|contains|all:
            - 'reg'
            - 'add'
    selection_cli_reg_start:
        CommandLine|contains|all:
            - 'd 4'
            - 'v Start'
        CommandLine|contains:
            - '\AppIDSvc'
            - '\MsMpSvc'
            - '\NisSrv'
            - '\SecurityHealthService'
            - '\Sense'
            - '\UsoSvc'
            - '\WdBoot'
            - '\WdFilter'
            - '\WdNisDrv'
            - '\WdNisSvc'
            - '\WinDefend'
            - '\wscsvc'
            - '\wuauserv'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```
