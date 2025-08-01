```sql
// Translated content (automatically translated on 01-08-2025 01:45:58):
event.type="Process Creation" and (endpoint.os="osx" and tgt.process.image.path="/usr/sbin/screencapture")
```


# Original Sigma Rule:
```yaml
title: Screen Capture - macOS
id: 0877ed01-da46-4c49-8476-d49cdd80dfa7
status: test
description: Detects attempts to use screencapture to collect macOS screenshots
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1113/T1113.md
    - https://github.com/EmpireProject/Empire/blob/08cbd274bef78243d7a8ed6443b8364acd1fc48b/lib/modules/python/collection/osx/screenshot.py
author: remotephone, oscd.community
date: 2020-10-13
modified: 2021-11-27
tags:
    - attack.collection
    - attack.t1113
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image: '/usr/sbin/screencapture'
    condition: selection
falsepositives:
    - Legitimate user activity taking screenshots
level: low
```
