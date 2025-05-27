```sql
// Translated content (automatically translated on 27-05-2025 01:18:01):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.cmdline contains ".bash_history" or tgt.process.cmdline contains ".zsh_history" or tgt.process.cmdline contains ".zhistory" or tgt.process.cmdline contains ".history" or tgt.process.cmdline contains ".sh_history" or tgt.process.cmdline contains "fish_history"))
```


# Original Sigma Rule:
```yaml
title: Suspicious History File Operations
id: 508a9374-ad52-4789-b568-fc358def2c65
status: test
description: Detects commandline operations on shell history files
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md
author: 'Mikhail Larin, oscd.community'
date: 2020-10-17
modified: 2021-11-27
tags:
    - attack.credential-access
    - attack.t1552.003
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '.bash_history'
            - '.zsh_history'
            - '.zhistory'
            - '.history'
            - '.sh_history'
            - 'fish_history'
    condition: selection
falsepositives:
    - Legitimate administrative activity
    - Legitimate software, cleaning hist file
level: medium
```
