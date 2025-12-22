```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\print.exe" and tgt.process.cmdline contains "print" and (tgt.process.cmdline contains "/D" and tgt.process.cmdline contains ".exe")) and (not tgt.process.cmdline contains "print.exe")))
```


# Original Sigma Rule:
```yaml
title: Abusing Print Executable
id: bafac3d6-7de9-4dd9-8874-4a1194b493ed
status: test
description: Attackers can use print.exe for remote file copy
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Print/
    - https://twitter.com/Oddvarmoe/status/985518877076541440
author: 'Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative'
date: 2020-10-05
modified: 2022-07-07
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\print.exe'
        CommandLine|startswith: 'print'
        CommandLine|contains|all:
            - '/D'
            - '.exe'
    filter_print:
        CommandLine|contains: 'print.exe'
    condition: selection and not filter_print
falsepositives:
    - Unknown
level: medium
```
