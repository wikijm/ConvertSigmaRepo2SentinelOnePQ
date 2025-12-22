```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "copy procdump" or tgt.process.cmdline contains "move procdump") or ((tgt.process.cmdline contains "copy " and tgt.process.cmdline contains ".dmp ") and (tgt.process.cmdline contains "2.dmp" or tgt.process.cmdline contains "lsass" or tgt.process.cmdline contains "out.dmp")) or (tgt.process.cmdline contains "copy lsass.exe_" or tgt.process.cmdline contains "move lsass.exe_")))
```


# Original Sigma Rule:
```yaml
title: Potential SysInternals ProcDump Evasion
id: 79b06761-465f-4f88-9ef2-150e24d3d737
status: test
description: Detects uses of the SysInternals ProcDump utility in which ProcDump or its output get renamed, or a dump file is moved or copied to a different name
references:
    - https://twitter.com/mrd0x/status/1480785527901204481
author: Florian Roth (Nextron Systems)
date: 2022-01-11
modified: 2023-05-09
tags:
    - attack.defense-evasion
    - attack.t1036
    - attack.t1003.001
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains:
            - 'copy procdump'
            - 'move procdump'
    selection_2:
        CommandLine|contains|all:
            - 'copy '
            - '.dmp '
        CommandLine|contains:
            - '2.dmp'
            - 'lsass'
            - 'out.dmp'
    selection_3:
        CommandLine|contains:
            - 'copy lsass.exe_'  # procdump default pattern e.g. lsass.exe_220111_085234.dmp
            - 'move lsass.exe_'  # procdump default pattern e.g. lsass.exe_220111_085234.dmp
    condition: 1 of selection_*
falsepositives:
    - False positives are expected in cases in which ProcDump just gets copied to a different directory without any renaming
level: high
```
