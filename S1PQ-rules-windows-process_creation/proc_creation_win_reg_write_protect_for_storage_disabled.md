```sql
// Translated content (automatically translated on 11-05-2025 02:07:55):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\System\CurrentControlSet\Control" and tgt.process.cmdline contains "Write Protection" and tgt.process.cmdline contains "0" and tgt.process.cmdline contains "storage"))
```


# Original Sigma Rule:
```yaml
title: Write Protect For Storage Disabled
id: 75f7a0e2-7154-4c4d-9eae-5cdb4e0a5c13
status: test
description: |
    Detects applications trying to modify the registry in order to disable any write-protect property for storage devices.
    This could be a precursor to a ransomware attack and has been an observed technique used by cypherpunk group.
references:
    - https://www.manageengine.com/products/desktop-central/os-imaging-deployment/media-is-write-protected.html
author: Sreeman
date: 2021-06-11
modified: 2024-01-18
tags:
    - attack.defense-evasion
    - attack.t1562
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - '\System\CurrentControlSet\Control'
            - 'Write Protection'
            - '0'
            - 'storage'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
