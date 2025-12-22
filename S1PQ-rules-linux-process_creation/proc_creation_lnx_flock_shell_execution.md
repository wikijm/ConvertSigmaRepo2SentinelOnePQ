```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/flock" and tgt.process.cmdline contains " -u ") and (tgt.process.cmdline contains "/bin/bash" or tgt.process.cmdline contains "/bin/dash" or tgt.process.cmdline contains "/bin/fish" or tgt.process.cmdline contains "/bin/sh" or tgt.process.cmdline contains "/bin/zsh")))
```


# Original Sigma Rule:
```yaml
title: Shell Execution via Flock - Linux
id: 4b09c71e-4269-4111-9cdd-107d8867f0cc
status: test
description: |
    Detects the use of the "flock" command to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/flock/#shell
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
        Image|endswith: '/flock'
        CommandLine|contains: ' -u '
    selection_cli:
        CommandLine|contains:
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/zsh'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
