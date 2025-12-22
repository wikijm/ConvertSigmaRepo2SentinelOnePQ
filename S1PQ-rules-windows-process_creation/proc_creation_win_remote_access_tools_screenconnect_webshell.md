```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\ScreenConnect.Service.exe" and (tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\csc.exe")))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - ScreenConnect Server Web Shell Execution
id: b19146a3-25d4-41b4-928b-1e2a92641b1b
status: test
description: Detects potential web shell execution from the ScreenConnect server process.
references:
    - https://blackpointcyber.com/resources/blog/breaking-through-the-screen/
    - https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8
author: Jason Rathbun (Blackpoint Cyber)
date: 2024-02-26
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\ScreenConnect.Service.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\csc.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
