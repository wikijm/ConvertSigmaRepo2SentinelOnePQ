```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (((tgt.process.image.path contains "/python" or tgt.process.image.path contains "/python2" or tgt.process.image.path contains "/python3") or (tgt.process.image.path contains "/python2." or tgt.process.image.path contains "/python3.")) and ((tgt.process.cmdline contains " -c " and tgt.process.cmdline contains "os.system(") and (tgt.process.cmdline contains "/bin/bash" or tgt.process.cmdline contains "/bin/dash" or tgt.process.cmdline contains "/bin/fish" or tgt.process.cmdline contains "/bin/sh" or tgt.process.cmdline contains "/bin/zsh"))))
```


# Original Sigma Rule:
```yaml
title: Inline Python Execution - Spawn Shell Via OS System Library
id: 2d2f44ff-4611-4778-a8fc-323a0e9850cc
status: test
description: |
    Detects execution of inline Python code via the "-c" in order to call the "system" function from the "os" library, and spawn a shell.
references:
    - https://gtfobins.github.io/gtfobins/python/#shell
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
        - Image|endswith:
              - '/python'
              - '/python2'
              - '/python3'
        - Image|contains:
              - '/python2.'  # python image is always of the form ../python3.10; ../python is just a symlink
              - '/python3.'
    selection_cli:
        CommandLine|contains|all:
            - ' -c '
            - 'os.system('
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
