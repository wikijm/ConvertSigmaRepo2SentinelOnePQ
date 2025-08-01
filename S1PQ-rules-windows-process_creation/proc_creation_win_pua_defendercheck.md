```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\DefenderCheck.exe" or tgt.process.displayName="DefenderCheck"))
```


# Original Sigma Rule:
```yaml
title: PUA - DefenderCheck Execution
id: f0ca6c24-3225-47d5-b1f5-352bf07ecfa7
status: test
description: Detects the use of DefenderCheck, a tool to evaluate the signatures used in Microsoft Defender. It can be used to figure out the strings / byte chains used in Microsoft Defender to detect a tool and thus used for AV evasion.
references:
    - https://github.com/matterpreter/DefenderCheck
author: Florian Roth (Nextron Systems)
date: 2022-08-30
modified: 2023-02-04
tags:
    - attack.defense-evasion
    - attack.t1027.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\DefenderCheck.exe'
        - Description: 'DefenderCheck'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
