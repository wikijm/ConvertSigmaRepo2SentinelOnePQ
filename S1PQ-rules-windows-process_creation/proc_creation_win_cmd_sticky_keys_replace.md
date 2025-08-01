```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "copy " and tgt.process.cmdline contains "/y " and tgt.process.cmdline contains "C:\windows\system32\cmd.exe C:\windows\system32\sethc.exe"))
```


# Original Sigma Rule:
```yaml
title: Persistence Via Sticky Key Backdoor
id: 1070db9a-3e5d-412e-8e7b-7183b616e1b3
status: test
description: |
    By replacing the sticky keys executable with the local admins CMD executable, an attacker is able to access a privileged windows console session without authenticating to the system.
    When the sticky keys are "activated" the privilleged shell is launched.
references:
    - https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html
    - https://www.clearskysec.com/wp-content/uploads/2020/02/ClearSky-Fox-Kitten-Campaign-v1.pdf
    - https://learn.microsoft.com/en-us/archive/blogs/jonathantrull/detecting-sticky-key-backdoors
author: Sreeman
date: 2020-02-18
modified: 2023-03-07
tags:
    - attack.t1546.008
    - attack.privilege-escalation
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'copy '
            - '/y '
            - 'C:\windows\system32\cmd.exe C:\windows\system32\sethc.exe'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```
