```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\eventvwr.exe" and (not (tgt.process.image.path contains ":\Windows\System32\mmc.exe" or tgt.process.image.path contains ":\Windows\System32\WerFault.exe" or tgt.process.image.path contains ":\Windows\SysWOW64\WerFault.exe"))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Event Viewer Child Process
id: be344333-921d-4c4d-8bb8-e584cf584780
related:
    - id: 7c81fec3-1c1d-43b0-996a-46753041b1b6
      type: derived
status: test
description: Detects uncommon or suspicious child processes of "eventvwr.exe" which might indicate a UAC bypass attempt
references:
    - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
    - https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100
author: Florian Roth (Nextron Systems)
date: 2017-03-19
modified: 2023-09-28
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
    - car.2019-04-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\eventvwr.exe'
    filter_main_generic:
        Image|endswith:
            - ':\Windows\System32\mmc.exe'
            - ':\Windows\System32\WerFault.exe'
            - ':\Windows\SysWOW64\WerFault.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
