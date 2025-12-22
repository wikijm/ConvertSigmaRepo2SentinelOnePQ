```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/ssh" and (tgt.process.cmdline contains "ProxyCommand=;" or tgt.process.cmdline contains "permitlocalcommand=yes" or tgt.process.cmdline contains "localhost")) and (tgt.process.cmdline contains "/bin/bash" or tgt.process.cmdline contains "/bin/dash" or tgt.process.cmdline contains "/bin/fish" or tgt.process.cmdline contains "/bin/sh" or tgt.process.cmdline contains "/bin/zsh" or tgt.process.cmdline contains "sh 0<&2 1>&2" or tgt.process.cmdline contains "sh 1>&2 0<&2")))
```


# Original Sigma Rule:
```yaml
title: Shell Invocation Via Ssh - Linux
id: 8737b7f6-8df3-4bb7-b1da-06019b99b687
status: test
description: |
    Detects the use of the "ssh" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/ssh/
    - https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-08-29
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/ssh'
        CommandLine|contains:
            - 'ProxyCommand=;'
            - 'permitlocalcommand=yes'
            - 'localhost'
    selection_cli:
        CommandLine|contains:
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/zsh'
            - 'sh 0<&2 1>&2'
            - 'sh 1>&2 0<&2'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
