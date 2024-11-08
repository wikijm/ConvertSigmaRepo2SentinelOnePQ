```sql
// Translated content (automatically translated on 08-11-2024 01:18:16):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.integrityLevel in ("High","System")) and tgt.process.image.path="C:\Windows\System32\ComputerDefaults.exe") and (not (src.process.image.path contains ":\Windows\System32" or src.process.image.path contains ":\Program Files"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Tools Using ComputerDefaults
id: 3c05e90d-7eba-4324-9972-5d7f711a60a8
status: test
description: Detects tools such as UACMe used to bypass UAC with computerdefaults.exe (UACMe 59)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-31
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        IntegrityLevel:
            - 'High'
            - 'System'
        Image: 'C:\Windows\System32\ComputerDefaults.exe'
    filter:
        ParentImage|contains:
            - ':\Windows\System32'
            - ':\Program Files'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
