```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\format.com" and tgt.process.cmdline contains "/fs:") and (not (tgt.process.cmdline contains "/fs:exFAT" or tgt.process.cmdline contains "/fs:FAT" or tgt.process.cmdline contains "/fs:NTFS" or tgt.process.cmdline contains "/fs:ReFS" or tgt.process.cmdline contains "/fs:UDF"))))
```


# Original Sigma Rule:
```yaml
title: Uncommon FileSystem Load Attempt By Format.com
id: 9fb6b26e-7f9e-4517-a48b-8cac4a1b6c60
status: test
description: |
    Detects the execution of format.com with an uncommon filesystem selection that could indicate a defense evasion activity in which "format.com" is used to load malicious DLL files or other programs.
references:
    - https://twitter.com/0gtweet/status/1477925112561209344
    - https://twitter.com/wdormann/status/1478011052130459653?s=20
author: Florian Roth (Nextron Systems)
date: 2022-01-04
modified: 2024-05-13
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\format.com'
        CommandLine|contains: '/fs:'
    filter_main_known_fs:
        CommandLine|contains:
            - '/fs:exFAT'
            - '/fs:FAT'
            - '/fs:NTFS'
            - '/fs:ReFS'
            - '/fs:UDF'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
