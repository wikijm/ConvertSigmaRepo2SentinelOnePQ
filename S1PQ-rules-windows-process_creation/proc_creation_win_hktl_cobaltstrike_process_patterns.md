```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "cmd.exe /C whoami" and src.process.image.path contains "C:\\Temp\\") or ((src.process.image.path contains "\\runonce.exe" or src.process.image.path contains "\\dllhost.exe") and (tgt.process.cmdline contains "cmd.exe /c echo" and tgt.process.cmdline contains "> \\\\.\\pipe")) or ((src.process.cmdline contains "cmd.exe /C echo" and src.process.cmdline contains " > \\\\.\\pipe") and tgt.process.cmdline contains "conhost.exe 0xffffffff -ForceV1") or (src.process.cmdline contains "/C whoami" and tgt.process.cmdline contains "conhost.exe 0xffffffff -ForceV1")))
```


# Original Sigma Rule:
```yaml
title: Potential CobaltStrike Process Patterns
id: f35c5d71-b489-4e22-a115-f003df287317
status: test
description: Detects potential process patterns related to Cobalt Strike beacon activity
references:
    - https://hausec.com/2021/07/26/cobalt-strike-and-tradecraft/
    - https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021-07-27
modified: 2023-03-29
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_generic_1:
        CommandLine|endswith: 'cmd.exe /C whoami'
        ParentImage|startswith: 'C:\Temp\'
    selection_generic_2:
        ParentImage|endswith:
            - '\runonce.exe'
            - '\dllhost.exe'
        CommandLine|contains|all:
            - 'cmd.exe /c echo'
            - '> \\\\.\\pipe'
    selection_conhost_1:
        ParentCommandLine|contains|all:
            - 'cmd.exe /C echo'
            - ' > \\\\.\\pipe'
        CommandLine|endswith: 'conhost.exe 0xffffffff -ForceV1'
    selection_conhost_2:
        ParentCommandLine|endswith: '/C whoami'
        CommandLine|endswith: 'conhost.exe 0xffffffff -ForceV1'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
