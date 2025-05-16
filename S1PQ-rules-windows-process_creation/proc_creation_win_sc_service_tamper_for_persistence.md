```sql
// Translated content (automatically translated on 16-05-2025 02:03:30):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "sc " and tgt.process.cmdline contains "config " and tgt.process.cmdline contains "binpath=") or (tgt.process.cmdline contains "sc " and tgt.process.cmdline contains "failure" and tgt.process.cmdline contains "command=")) or (((tgt.process.cmdline contains "reg " and tgt.process.cmdline contains "add " and tgt.process.cmdline contains "FailureCommand") or (tgt.process.cmdline contains "reg " and tgt.process.cmdline contains "add " and tgt.process.cmdline contains "ImagePath")) and (tgt.process.cmdline contains ".sh" or tgt.process.cmdline contains ".exe" or tgt.process.cmdline contains ".dll" or tgt.process.cmdline contains ".bin$" or tgt.process.cmdline contains ".bat" or tgt.process.cmdline contains ".cmd" or tgt.process.cmdline contains ".js" or tgt.process.cmdline contains ".msh$" or tgt.process.cmdline contains ".reg$" or tgt.process.cmdline contains ".scr" or tgt.process.cmdline contains ".ps" or tgt.process.cmdline contains ".vb" or tgt.process.cmdline contains ".jar" or tgt.process.cmdline contains ".pl"))))
```


# Original Sigma Rule:
```yaml
title: Potential Persistence Attempt Via Existing Service Tampering
id: 38879043-7e1e-47a9-8d46-6bec88e201df
status: test
description: Detects the modification of an existing service in order to execute an arbitrary payload when the service is started or killed as a potential method for persistence.
references:
    - https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/
author: Sreeman
date: 2020-09-29
modified: 2023-02-04
tags:
    - attack.persistence
    - attack.t1543.003
    - attack.t1574.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_sc:
        - CommandLine|contains|all:
              - 'sc '
              - 'config '
              - 'binpath='
        - CommandLine|contains|all:
              - 'sc '
              - 'failure'
              - 'command='
    selection_reg_img:
        - CommandLine|contains|all:
              - 'reg '
              - 'add '
              - 'FailureCommand'
        - CommandLine|contains|all:
              - 'reg '
              - 'add '
              - 'ImagePath'
    selection_reg_ext:
        CommandLine|contains:
            - '.sh'
            - '.exe'
            - '.dll'
            - '.bin$'
            - '.bat'
            - '.cmd'
            - '.js'
            - '.msh$'
            - '.reg$'
            - '.scr'
            - '.ps'
            - '.vb'
            - '.jar'
            - '.pl'
    condition: selection_sc or all of selection_reg_*
falsepositives:
    - Unknown
level: medium
```
