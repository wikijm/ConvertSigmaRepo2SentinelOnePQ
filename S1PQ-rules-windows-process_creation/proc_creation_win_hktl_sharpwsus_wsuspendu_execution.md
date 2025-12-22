```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " -Inject " and (tgt.process.cmdline contains " -PayloadArgs " or tgt.process.cmdline contains " -PayloadFile ")) or ((tgt.process.cmdline contains " approve " or tgt.process.cmdline contains " create " or tgt.process.cmdline contains " check " or tgt.process.cmdline contains " delete ") and (tgt.process.cmdline contains " /payload:" or tgt.process.cmdline contains " /payload=" or tgt.process.cmdline contains " /updateid:" or tgt.process.cmdline contains " /updateid="))))
```


# Original Sigma Rule:
```yaml
title: HackTool - SharpWSUS/WSUSpendu Execution
id: b0ce780f-10bd-496d-9067-066d23dc3aa5
status: test
description: |
    Detects the execution of SharpWSUS or WSUSpendu, utilities that allow for lateral movement through WSUS.
    Windows Server Update Services (WSUS) is a critical component of Windows systems and is frequently configured in a way that allows an attacker to circumvent internal networking limitations.
references:
    - https://labs.nettitude.com/blog/introducing-sharpwsus/
    - https://github.com/nettitude/SharpWSUS
    - https://web.archive.org/web/20210512154016/https://github.com/AlsidOfficial/WSUSpendu/blob/master/WSUSpendu.ps1
author: '@Kostastsale, Nasreddine Bencherchali (Nextron Systems)'
date: 2022-10-07
modified: 2024-08-23
tags:
    - attack.execution
    - attack.lateral-movement
    - attack.t1210
logsource:
    product: windows
    category: process_creation
detection:
    selection_wsuspendu_inject:
        CommandLine|contains: ' -Inject '
    selection_wsuspendu_payload:
        CommandLine|contains:
            - ' -PayloadArgs '
            - ' -PayloadFile '
    selection_sharpwsus_commands:
        CommandLine|contains:
            - ' approve '
            - ' create '
            - ' check '
            - ' delete '
    selection_sharpwsus_flags:
        CommandLine|contains:
            - ' /payload:'
            - ' /payload='
            - ' /updateid:'
            - ' /updateid='
    condition: all of selection_wsuspendu_* or all of selection_sharpwsus_*
falsepositives:
    - Unknown
level: high
```
