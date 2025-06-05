```sql
// Translated content (automatically translated on 05-06-2025 00:56:25):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "grep" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/tail" or tgt.process.image.path contains "/more") and tgt.process.cmdline contains " /etc/sudoers"))
```


# Original Sigma Rule:
```yaml
title: Cat Sudoers
id: 0f79c4d2-4e1f-4683-9c36-b5469a665e06
status: test
description: Detects the execution of a cat /etc/sudoers to list all users that have sudo rights
references:
    - https://github.com/sleventyeleven/linuxprivchecker/
author: Florian Roth (Nextron Systems)
date: 2022-06-20
modified: 2022-09-15
tags:
    - attack.reconnaissance
    - attack.t1592.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/cat'
            - 'grep'
            - '/head'
            - '/tail'
            - '/more'
        CommandLine|contains: ' /etc/sudoers'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
