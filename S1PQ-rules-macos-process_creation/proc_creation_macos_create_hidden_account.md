```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (((tgt.process.image.path contains "/dscl" and tgt.process.cmdline contains "create") and (tgt.process.cmdline contains "UniqueID" and tgt.process.cmdline matches "([0-9]|[1-9][0-9]|[1-4][0-9]{2})")) or ((tgt.process.image.path contains "/dscl" and tgt.process.cmdline contains "create") and (tgt.process.cmdline contains "IsHidden" and (tgt.process.cmdline contains "true" or tgt.process.cmdline contains "yes" or tgt.process.cmdline contains "1")))))
```


# Original Sigma Rule:
```yaml
title: Hidden User Creation
id: b22a5b36-2431-493a-8be1-0bae56c28ef3
status: test
description: Detects creation of a hidden user account on macOS (UserID < 500) or with IsHidden option
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.002/T1564.002.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-10
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.t1564.002
logsource:
    category: process_creation
    product: macos
detection:
    dscl_create:
        Image|endswith: '/dscl'
        CommandLine|contains: 'create'
    id_below_500:
        CommandLine|contains: UniqueID
        CommandLine|re: '([0-9]|[1-9][0-9]|[1-4][0-9]{2})'
    ishidden_option_declaration:
        CommandLine|contains: 'IsHidden'
    ishidden_option_confirmation:
        CommandLine|contains:
            - 'true'
            - 'yes'
            - '1'
    condition: dscl_create and id_below_500 or dscl_create and (ishidden_option_declaration and ishidden_option_confirmation)
falsepositives:
    - Legitimate administration activities
level: medium
```
