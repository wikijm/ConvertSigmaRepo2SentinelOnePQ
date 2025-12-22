```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "taskkill " and tgt.process.cmdline contains "RaccineSettings.exe") or (tgt.process.cmdline contains "reg.exe" and tgt.process.cmdline contains "delete" and tgt.process.cmdline contains "Raccine Tray") or (tgt.process.cmdline contains "schtasks" and tgt.process.cmdline contains "/DELETE" and tgt.process.cmdline contains "Raccine Rules Updater")))
```


# Original Sigma Rule:
```yaml
title: Raccine Uninstall
id: a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc
status: test
description: Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool.
references:
    - https://github.com/Neo23x0/Raccine
author: Florian Roth (Nextron Systems)
date: 2021-01-21
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all:
            - 'taskkill '
            - 'RaccineSettings.exe'
    selection2:
        CommandLine|contains|all:
            - 'reg.exe'
            - 'delete'
            - 'Raccine Tray'
    selection3:
        CommandLine|contains|all:
            - 'schtasks'
            - '/DELETE'
            - 'Raccine Rules Updater'
    condition: 1 of selection*
falsepositives:
    - Legitimate deinstallation by administrative staff
level: high
```
