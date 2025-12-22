```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (((tgt.process.image.path contains "/rsync" or tgt.process.image.path contains "/rsyncd") and tgt.process.cmdline contains " -e ") and (tgt.process.cmdline contains "/ash " or tgt.process.cmdline contains "/bash " or tgt.process.cmdline contains "/dash " or tgt.process.cmdline contains "/csh " or tgt.process.cmdline contains "/sh " or tgt.process.cmdline contains "/zsh " or tgt.process.cmdline contains "/tcsh " or tgt.process.cmdline contains "/ksh " or tgt.process.cmdline contains "'ash " or tgt.process.cmdline contains "'bash " or tgt.process.cmdline contains "'dash " or tgt.process.cmdline contains "'csh " or tgt.process.cmdline contains "'sh " or tgt.process.cmdline contains "'zsh " or tgt.process.cmdline contains "'tcsh " or tgt.process.cmdline contains "'ksh ")))
```


# Original Sigma Rule:
```yaml
title: Shell Execution via Rsync - Linux
id: e2326866-609f-4015-aea9-7ec634e8aa04
status: experimental
description: |
    Detects the use of the "rsync" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/rsync/#shell
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.), Florian Roth
date: 2024-09-02
modified: 2025-01-18
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/rsync'
            - '/rsyncd'
        CommandLine|contains: ' -e '
    selection_cli:
        CommandLine|contains:
            - '/ash '
            - '/bash '
            - '/dash '
            - '/csh '
            - '/sh '
            - '/zsh '
            - '/tcsh '
            - '/ksh '
            - "'ash "
            - "'bash "
            - "'dash "
            - "'csh "
            - "'sh "
            - "'zsh "
            - "'tcsh "
            - "'ksh "
    condition: all of selection_*
falsepositives:
    - Legitimate cases in which "rsync" is used to execute a shell
level: high
```
