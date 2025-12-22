```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/nice" and (tgt.process.cmdline contains "/bin/bash" or tgt.process.cmdline contains "/bin/dash" or tgt.process.cmdline contains "/bin/fish" or tgt.process.cmdline contains "/bin/sh" or tgt.process.cmdline contains "/bin/zsh")))
```


# Original Sigma Rule:
```yaml
title: Shell Execution via Nice - Linux
id: 093d68c7-762a-42f4-9f46-95e79142571a
status: test
description: |
    Detects the use of the "nice" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/nice/#shell
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
    selection:
        Image|endswith: '/nice'
        CommandLine|endswith:
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/zsh'
    condition: selection
falsepositives:
    - Unknown
level: high
```
