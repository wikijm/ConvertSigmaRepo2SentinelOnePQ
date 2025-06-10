```sql
// Translated content (automatically translated on 10-06-2025 02:08:00):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\dtrace.exe" and tgt.process.cmdline contains "lkd(0)") or (tgt.process.cmdline contains "syscall:::return" and tgt.process.cmdline contains "lkd(")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Kernel Dump Using Dtrace
id: 7124aebe-4cd7-4ccb-8df0-6d6b93c96795
status: test
description: Detects suspicious way to dump the kernel on Windows systems using dtrace.exe, which is available on Windows systems since Windows 10 19H1
references:
    - https://twitter.com/0gtweet/status/1474899714290208777?s=12
    - https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace
author: Florian Roth (Nextron Systems)
date: 2021-12-28
tags:
    - attack.discovery
    - attack.t1082
logsource:
    product: windows
    category: process_creation
detection:
    selection_plain:
        Image|endswith: '\dtrace.exe'
        CommandLine|contains: 'lkd(0)'
    selection_obfuscated:
        CommandLine|contains|all:
            - 'syscall:::return'
            - 'lkd('
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
