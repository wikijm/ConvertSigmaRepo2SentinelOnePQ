```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "\\HarddiskVolumeShadowCopy" and tgt.process.cmdline contains "System32\\config\\sam") and (tgt.process.cmdline contains "Copy-Item" or tgt.process.cmdline contains "cp $_." or tgt.process.cmdline contains "cpi $_." or tgt.process.cmdline contains "copy $_." or tgt.process.cmdline contains ".File]::Copy(")))
```


# Original Sigma Rule:
```yaml
title: PowerShell SAM Copy
id: 1af57a4b-460a-4738-9034-db68b880c665
status: test
description: Detects suspicious PowerShell scripts accessing SAM hives
references:
    - https://twitter.com/splinter_code/status/1420546784250769408
author: Florian Roth (Nextron Systems)
date: 2021-07-29
modified: 2023-01-06
tags:
    - attack.credential-access
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains|all:
            - '\HarddiskVolumeShadowCopy'
            - 'System32\config\sam'
    selection_2:
        CommandLine|contains:
            - 'Copy-Item'
            - 'cp $_.'
            - 'cpi $_.'
            - 'copy $_.'
            - '.File]::Copy('
    condition: all of selection*
falsepositives:
    - Some rare backup scenarios
    - PowerShell scripts fixing HiveNightmare / SeriousSAM ACLs
level: high
```
