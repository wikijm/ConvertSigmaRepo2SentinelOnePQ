```sql
// Translated content (automatically translated on 28-09-2025 02:03:26):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\\calc.exe " or (tgt.process.image.path contains "\\calc.exe" and (not (tgt.process.image.path contains ":\\Windows\\System32\\" or tgt.process.image.path contains ":\\Windows\\SysWOW64\\" or tgt.process.image.path contains ":\\Windows\\WinSxS\\")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Calculator Usage
id: 737e618a-a410-49b5-bec3-9e55ff7fbc15
status: test
description: |
    Detects suspicious use of 'calc.exe' with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion.
references:
    - https://twitter.com/ItsReallyNick/status/1094080242686312448
author: Florian Roth (Nextron Systems)
date: 2019-02-09
modified: 2023-11-09
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains: '\calc.exe '
    selection_2:
        Image|endswith: '\calc.exe'
    filter_main_known_locations:
        Image|contains:
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
            - ':\Windows\WinSxS\'
    condition: selection_1 or ( selection_2 and not filter_main_known_locations )
falsepositives:
    - Unknown
level: high
```
