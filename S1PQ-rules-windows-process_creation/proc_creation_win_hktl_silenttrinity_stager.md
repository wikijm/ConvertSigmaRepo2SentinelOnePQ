```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.displayName contains "st2stager")
```


# Original Sigma Rule:
```yaml
title: HackTool - SILENTTRINITY Stager Execution
id: 03552375-cc2c-4883-bbe4-7958d5a980be
related:
    - id: 75c505b1-711d-4f68-a357-8c3fe37dbf2d # DLL Load
      type: derived
status: test
description: Detects SILENTTRINITY stager use via PE metadata
references:
    - https://github.com/byt3bl33d3r/SILENTTRINITY
author: Aleksey Potapov, oscd.community
date: 2019-10-22
modified: 2023-02-13
tags:
    - attack.command-and-control
    - attack.t1071
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description|contains: 'st2stager'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
