```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/touch" and (tgt.process.cmdline contains "-t" or tgt.process.cmdline contains "-acmr" or tgt.process.cmdline contains "-d" or tgt.process.cmdline contains "-r")))
```


# Original Sigma Rule:
```yaml
title: File Time Attribute Change
id: 88c0f9d8-30a8-4120-bb6b-ebb54abcf2a0
status: test
description: Detect file time attribute change to hide new or changes to existing files
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.006/T1070.006.md
author: Igor Fits, Mikhail Larin, oscd.community
date: 2020-10-19
modified: 2022-01-12
tags:
    - attack.defense-evasion
    - attack.t1070.006
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: '/touch'
        CommandLine|contains:
            - '-t'
            - '-acmr'
            - '-d'
            - '-r'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
