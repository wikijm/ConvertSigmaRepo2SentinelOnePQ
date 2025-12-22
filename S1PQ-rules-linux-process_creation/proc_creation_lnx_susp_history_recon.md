```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/tail" or tgt.process.image.path contains "/more") and ((tgt.process.cmdline contains "/.bash_history" or tgt.process.cmdline contains "/.zsh_history") or (tgt.process.cmdline contains "_history" or tgt.process.cmdline contains ".history" or tgt.process.cmdline contains "zhistory"))))
```


# Original Sigma Rule:
```yaml
title: Print History File Contents
id: d7821ff1-4527-4e33-9f84-d0d57fa2fb66
status: test
description: Detects events in which someone prints the contents of history files to the commandline or redirects it to a file for reconnaissance
references:
    - https://github.com/sleventyeleven/linuxprivchecker/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md
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
            - '/head'
            - '/tail'
            - '/more'
    selection_history:
        - CommandLine|contains:
              - '/.bash_history'
              - '/.zsh_history'
        - CommandLine|endswith:
              - '_history'
              - '.history'
              - 'zhistory'
    condition: all of selection*
falsepositives:
    - Legitimate administration activities
level: medium
```
