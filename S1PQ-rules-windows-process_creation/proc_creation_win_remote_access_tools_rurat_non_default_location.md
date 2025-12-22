```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\rutserv.exe" or tgt.process.image.path contains "\\rfusclient.exe") or tgt.process.displayName="Remote Utilities") and (not (tgt.process.image.path contains "C:\\Program Files\\Remote Utilities" or tgt.process.image.path contains "C:\\Program Files (x86)\\Remote Utilities"))))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - RURAT Execution From Unusual Location
id: e01fa958-6893-41d4-ae03-182477c5e77d
status: test
description: Detects execution of Remote Utilities RAT (RURAT) from an unusual location (outside of 'C:\Program Files')
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-19
modified: 2023-03-05
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\rutserv.exe'
              - '\rfusclient.exe'
        - Product: 'Remote Utilities'
    filter:
        Image|startswith:
            - 'C:\Program Files\Remote Utilities'
            - 'C:\Program Files (x86)\Remote Utilities'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
