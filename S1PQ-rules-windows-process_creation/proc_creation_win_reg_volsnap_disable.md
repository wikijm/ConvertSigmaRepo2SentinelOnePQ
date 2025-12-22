```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\\Services\\VSS\\Diag" and tgt.process.cmdline contains "/d Disabled"))
```


# Original Sigma Rule:
```yaml
title: Disabled Volume Snapshots
id: dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a
status: test
description: Detects commands that temporarily turn off Volume Snapshots
references:
    - https://twitter.com/0gtweet/status/1354766164166115331
author: Florian Roth (Nextron Systems)
date: 2021-01-28
modified: 2023-12-15
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\Services\VSS\Diag'
            - '/d Disabled'
    condition: selection
falsepositives:
    - Legitimate administration
level: high
```
