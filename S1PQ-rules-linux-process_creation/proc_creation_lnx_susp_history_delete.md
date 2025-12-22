```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/rm" or tgt.process.image.path contains "/unlink" or tgt.process.image.path contains "/shred") and ((tgt.process.cmdline contains "/.bash_history" or tgt.process.cmdline contains "/.zsh_history") or (tgt.process.cmdline contains "_history" or tgt.process.cmdline contains ".history" or tgt.process.cmdline contains "zhistory"))))
```


# Original Sigma Rule:
```yaml
title: History File Deletion
id: 1182f3b3-e716-4efa-99ab-d2685d04360f
status: test
description: Detects events in which a history file gets deleted, e.g. the ~/bash_history to remove traces of malicious activity
references:
    - https://github.com/sleventyeleven/linuxprivchecker/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md
author: Florian Roth (Nextron Systems)
date: 2022-06-20
modified: 2022-09-15
tags:
    - attack.impact
    - attack.t1565.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/rm'
            - '/unlink'
            - '/shred'
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
level: high
```
