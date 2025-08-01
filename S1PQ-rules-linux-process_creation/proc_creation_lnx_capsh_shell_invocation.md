```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/capsh" and tgt.process.cmdline contains " --"))
```


# Original Sigma Rule:
```yaml
title: Capsh Shell Invocation - Linux
id: db1ac3be-f606-4e3a-89e0-9607cbe6b98a
status: test
description: |
    Detects the use of the "capsh" utility to invoke a shell.
references:
    - https://gtfobins.github.io/gtfobins/capsh/#shell
    - https://www.elastic.co/guide/en/security/current/linux-restricted-shell-breakout-via-linux-binary-s.html
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
        Image|endswith: '/capsh'
        CommandLine|endswith: ' --'
    condition: selection
falsepositives:
    - Unknown
level: high
```
