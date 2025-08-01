```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\ScreenConnect.ClientService.exe")
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - ScreenConnect Remote Command Execution - Hunting
id: d1a401ab-8c47-4e86-a7d8-2460b6a53e4a
related:
    - id: b1f73849-6329-4069-bc8f-78a604bb8b23
      type: derived
    - id: 7b582f1a-b318-4c6a-bf4e-66fe49bf55a5
      type: derived
status: test
description: |
    Detects remote binary or command execution via the ScreenConnect Service.
    Use this rule in order to hunt for potentially anomalous executions originating from ScreenConnect
references:
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-02-23
modified: 2024-02-26
tags:
    - attack.execution
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\ScreenConnect.ClientService.exe'
    condition: selection
falsepositives:
    - Legitimate commands launched from ScreenConnect will also trigger this rule. Look for anomalies.
level: medium
```
