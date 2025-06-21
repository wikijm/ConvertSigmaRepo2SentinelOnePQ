```sql
// Translated content (automatically translated on 21-06-2025 00:56:11):
event.type="Process Creation" and (endpoint.os="linux" and (src.process.image.path contains "/git" and (src.process.cmdline contains " -p " and src.process.cmdline contains "help") and (tgt.process.cmdline contains "bash 0<&1" or tgt.process.cmdline contains "dash 0<&1" or tgt.process.cmdline contains "sh 0<&1")))
```


# Original Sigma Rule:
```yaml
title: Shell Execution via Git - Linux
id: 47b3bbd4-1bf7-48cc-84ab-995362aaa75a
status: experimental
description: |
    Detects the use of the "git" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/git/#shell
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith: '/git'
        ParentCommandLine|contains|all:
            - ' -p '
            - 'help'
        CommandLine|contains:
            - 'bash 0<&1'
            - 'dash 0<&1'
            - 'sh 0<&1'
    condition: selection
falsepositives:
    - Unknown
level: high
```
