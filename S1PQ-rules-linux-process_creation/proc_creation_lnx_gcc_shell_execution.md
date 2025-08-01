```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (((tgt.process.image.path contains "/c89" or tgt.process.image.path contains "/c99" or tgt.process.image.path contains "/gcc") and tgt.process.cmdline contains "-wrapper") and (tgt.process.cmdline contains "/bin/bash,-s" or tgt.process.cmdline contains "/bin/dash,-s" or tgt.process.cmdline contains "/bin/fish,-s" or tgt.process.cmdline contains "/bin/sh,-s" or tgt.process.cmdline contains "/bin/zsh,-s")))
```


# Original Sigma Rule:
```yaml
title: Shell Execution GCC  - Linux
id: 9b5de532-a757-4d70-946c-1f3e44f48b4d
status: test
description: |
    Detects the use of the "gcc" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/gcc/#shell
    - https://gtfobins.github.io/gtfobins/c89/#shell
    - https://gtfobins.github.io/gtfobins/c99/#shell
    - https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/c89'
            - '/c99'
            - '/gcc'
        CommandLine|contains: '-wrapper'
    selection_cli:
        CommandLine|contains:
            - '/bin/bash,-s'
            - '/bin/dash,-s'
            - '/bin/fish,-s'
            - '/bin/sh,-s'
            - '/bin/zsh,-s'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
