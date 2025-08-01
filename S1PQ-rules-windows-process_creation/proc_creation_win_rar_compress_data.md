```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\rar.exe" and tgt.process.cmdline contains " a "))
```


# Original Sigma Rule:
```yaml
title: Files Added To An Archive Using Rar.EXE
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
status: test
description: Detects usage of "rar" to add files to an archive for potential compression. An adversary may compress data (e.g. sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
    - https://eqllib.readthedocs.io/en/latest/analytics/1ec33c93-3d0b-4a28-8014-dbdaae5c60ae.html
author: Timur Zinniatullin, E.M. Anhaus, oscd.community
date: 2019-10-21
modified: 2023-02-05
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rar.exe'
        CommandLine|contains: ' a '
    condition: selection
falsepositives:
    - Highly likely if rar is a default archiver in the monitored environment.
level: low
```
