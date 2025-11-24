```sql
// Translated content (automatically translated on 24-11-2025 02:10:29):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.displayName="Remote Utilities" and (not (tgt.process.image.path contains "\\rutserv.exe" or tgt.process.image.path contains "\\rfusclient.exe"))))
```


# Original Sigma Rule:
```yaml
title: Renamed Remote Utilities RAT (RURAT) Execution
id: 9ef27c24-4903-4192-881a-3adde7ff92a5
status: test
description: Detects execution of renamed Remote Utilities (RURAT) via Product PE header field
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-19
modified: 2023-02-03
tags:
    - attack.defense-evasion
    - attack.collection
    - attack.command-and-control
    - attack.discovery
    - attack.s0592
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Product: 'Remote Utilities'
    filter:
        Image|endswith:
            - '\rutserv.exe'
            - '\rfusclient.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
