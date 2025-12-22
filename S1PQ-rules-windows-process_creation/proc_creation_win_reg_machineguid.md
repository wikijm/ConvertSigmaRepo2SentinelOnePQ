```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\reg.exe" and (tgt.process.cmdline contains "SOFTWARE\\Microsoft\\Cryptography" and tgt.process.cmdline contains "/v " and tgt.process.cmdline contains "MachineGuid")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Query of MachineGUID
id: f5240972-3938-4e56-8e4b-e33893176c1f
status: test
description: Use of reg to get MachineGuid information
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-8---windows-machineguid-discovery
author: frack113
date: 2022-01-01
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - 'SOFTWARE\Microsoft\Cryptography'
            - '/v '
            - 'MachineGuid'
    condition: selection
falsepositives:
    - Unknown
level: low
```
