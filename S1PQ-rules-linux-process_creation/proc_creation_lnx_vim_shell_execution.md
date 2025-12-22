```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (((tgt.process.image.path contains "/rvim" or tgt.process.image.path contains "/vim" or tgt.process.image.path contains "/vimdiff") and (tgt.process.cmdline contains " --cmd" or tgt.process.cmdline contains " -c ")) and (tgt.process.cmdline contains ":!/" or tgt.process.cmdline contains ":lua " or tgt.process.cmdline contains ":py " or tgt.process.cmdline contains "/bin/bash" or tgt.process.cmdline contains "/bin/dash" or tgt.process.cmdline contains "/bin/fish" or tgt.process.cmdline contains "/bin/sh" or tgt.process.cmdline contains "/bin/zsh")))
```


# Original Sigma Rule:
```yaml
title: Vim GTFOBin Abuse - Linux
id: 7ab8f73a-fcff-428b-84aa-6a5ff7877dea
status: test
description: |
    Detects the use of "vim" and it's siblings commands to execute a shell or proxy commands.
    Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/vim/
    - https://gtfobins.github.io/gtfobins/rvim/
    - https://gtfobins.github.io/gtfobins/vimdiff/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-28
modified: 2024-09-02
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/rvim'
            - '/vim'
            - '/vimdiff'
        CommandLine|contains:
            - ' --cmd'
            - ' -c '
    selection_cli:
        CommandLine|contains:
            - ':!/'
            - ':lua '
            - ':py '
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
