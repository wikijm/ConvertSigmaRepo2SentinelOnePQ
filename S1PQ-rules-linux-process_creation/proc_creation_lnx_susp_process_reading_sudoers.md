```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/ed" or tgt.process.image.path contains "/egrep" or tgt.process.image.path contains "/emacs" or tgt.process.image.path contains "/fgrep" or tgt.process.image.path contains "/grep" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/less" or tgt.process.image.path contains "/more" or tgt.process.image.path contains "/nano" or tgt.process.image.path contains "/tail") and tgt.process.cmdline contains " /etc/sudoers"))
```


# Original Sigma Rule:
```yaml
title: Access of Sudoers File Content
id: 0f79c4d2-4e1f-4683-9c36-b5469a665e06
status: test
description: Detects the execution of a text-based file access or inspection utilities to read the content of /etc/sudoers in order to potentially list all users that have sudo rights.
references:
    - https://github.com/sleventyeleven/linuxprivchecker/
author: Florian Roth (Nextron Systems)
date: 2022-06-20
modified: 2025-06-04
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
            - '/ed'
            - '/egrep'
            - '/emacs'
            - '/fgrep'
            - '/grep'
            - '/head'
            - '/less'
            - '/more'
            - '/nano'
            - '/tail'
        CommandLine|contains: ' /etc/sudoers'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
