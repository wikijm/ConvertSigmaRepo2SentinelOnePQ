```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/shutdown" or tgt.process.image.path contains "/reboot" or tgt.process.image.path contains "/halt"))
```


# Original Sigma Rule:
```yaml
title: System Shutdown/Reboot - MacOs
id: 40b1fbe2-18ea-4ee7-be47-0294285811de
status: test
description: Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1529/T1529.md
author: 'Igor Fits, Mikhail Larin, oscd.community'
date: 2020-10-19
modified: 2022-11-26
tags:
    - attack.impact
    - attack.t1529
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/shutdown'
            - '/reboot'
            - '/halt'
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: informational
```
