```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and tgt.process.image.path contains "/split")
```


# Original Sigma Rule:
```yaml
title: Split A File Into Pieces
id: 7f2bb9d5-6395-4de5-969c-70c11fbe6b12
status: test
description: Detection use of the command "split" to split files into parts and possible transfer.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1030/T1030.md
author: 'Igor Fits, Mikhail Larin, oscd.community'
date: 2020-10-15
modified: 2021-11-27
tags:
    - attack.exfiltration
    - attack.t1030
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: '/split'
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: low
```
