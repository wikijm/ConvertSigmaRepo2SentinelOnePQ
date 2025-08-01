```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\.exe")
```


# Original Sigma Rule:
```yaml
title: Process Launched Without Image Name
id: f208d6d8-d83a-4c2c-960d-877c37da84e5
status: test
description: Detect the use of processes with no name (".exe"), which can be used to evade Image-based detections.
references:
    - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
author: Matt Anderson (Huntress)
date: 2024-07-23
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\.exe'
    condition: selection
falsepositives:
    - Rare legitimate software.
level: medium
```
