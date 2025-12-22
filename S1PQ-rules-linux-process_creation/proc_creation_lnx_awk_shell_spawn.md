```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (((tgt.process.image.path contains "/awk" or tgt.process.image.path contains "/gawk" or tgt.process.image.path contains "/mawk" or tgt.process.image.path contains "/nawk") and tgt.process.cmdline contains "BEGIN {system") and (tgt.process.cmdline contains "/bin/bash" or tgt.process.cmdline contains "/bin/dash" or tgt.process.cmdline contains "/bin/fish" or tgt.process.cmdline contains "/bin/sh" or tgt.process.cmdline contains "/bin/zsh")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Invocation of Shell via AWK - Linux
id: 8c1a5675-cb85-452f-a298-b01b22a51856
status: test
description: |
    Detects the execution of "awk" or it's sibling commands, to invoke a shell using the system() function.
    This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation.
references:
    - https://gtfobins.github.io/gtfobins/awk/#shell
    - https://gtfobins.github.io/gtfobins/gawk/#shell
    - https://gtfobins.github.io/gtfobins/nawk/#shell
    - https://gtfobins.github.io/gtfobins/mawk/#shell
author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
date: 2024-09-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/awk'
            - '/gawk'
            - '/mawk'
            - '/nawk'
        CommandLine|contains: 'BEGIN {system'
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
