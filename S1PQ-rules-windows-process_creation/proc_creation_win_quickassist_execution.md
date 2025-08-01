```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\QuickAssist.exe")
```


# Original Sigma Rule:
```yaml
title: QuickAssist Execution
id: e20b5b14-ce93-4230-88af-981983ef6e74
status: experimental
description: |
    Detects the execution of Microsoft Quick Assist tool "QuickAssist.exe". This utility can be used by attackers to gain remote access.
references:
    - https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/
    - https://www.linkedin.com/posts/kevin-beaumont-security_ive-been-assisting-a-few-orgs-hit-with-successful-activity-7268055739116445701-xxjZ/
    - https://x.com/cyb3rops/status/1862406110365245506
    - https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist
author: Muhammad Faisal (@faisalusuf)
date: 2024-12-19
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\QuickAssist.exe'
    condition: selection
falsepositives:
    - Legitimate use of Quick Assist in the environment.
level: low
```
