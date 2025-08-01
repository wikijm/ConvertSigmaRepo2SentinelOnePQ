```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and Description contains "st2stager")
```


# Original Sigma Rule:
```yaml
title: HackTool - SILENTTRINITY Stager DLL Load
id: 75c505b1-711d-4f68-a357-8c3fe37dbf2d
related:
    - id: 03552375-cc2c-4883-bbe4-7958d5a980be # Process Creation
      type: derived
status: test
description: Detects SILENTTRINITY stager dll loading activity
references:
    - https://github.com/byt3bl33d3r/SILENTTRINITY
author: Aleksey Potapov, oscd.community
date: 2019-10-22
modified: 2023-02-17
tags:
    - attack.command-and-control
    - attack.t1071
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Description|contains: 'st2stager'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
