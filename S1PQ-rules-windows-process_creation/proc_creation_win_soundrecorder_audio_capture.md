```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\SoundRecorder.exe" and tgt.process.cmdline contains "/FILE"))
```


# Original Sigma Rule:
```yaml
title: Audio Capture via SoundRecorder
id: 83865853-59aa-449e-9600-74b9d89a6d6e
status: test
description: Detect attacker collecting audio via SoundRecorder application.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1123/T1123.md
    - https://eqllib.readthedocs.io/en/latest/analytics/f72a98cb-7b3d-4100-99c3-a138b6e9ff6e.html
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: 2019-10-24
modified: 2021-11-27
tags:
    - attack.collection
    - attack.t1123
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\SoundRecorder.exe'
        CommandLine|contains: '/FILE'
    condition: selection
falsepositives:
    - Legitimate audio capture by legitimate user.
level: medium
```
