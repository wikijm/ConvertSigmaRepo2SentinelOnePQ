```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains ":\RECYCLER\" or tgt.process.image.path contains ":\SystemVolumeInformation\") or (tgt.process.image.path contains "C:\Windows\Tasks\" or tgt.process.image.path contains "C:\Windows\debug\" or tgt.process.image.path contains "C:\Windows\fonts\" or tgt.process.image.path contains "C:\Windows\help\" or tgt.process.image.path contains "C:\Windows\drivers\" or tgt.process.image.path contains "C:\Windows\addins\" or tgt.process.image.path contains "C:\Windows\cursors\" or tgt.process.image.path contains "C:\Windows\system32\tasks\")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Process Start Locations
id: 15b75071-74cc-47e0-b4c6-b43744a62a2b
status: test
description: Detects suspicious process run from unusual locations
references:
    - https://car.mitre.org/wiki/CAR-2013-05-002
author: juju4, Jonhnathan Ribeiro, oscd.community
date: 2019-01-16
modified: 2022-01-07
tags:
    - attack.defense-evasion
    - attack.t1036
    - car.2013-05-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|contains:
              - ':\RECYCLER\'
              - ':\SystemVolumeInformation\'
        - Image|startswith:
              - 'C:\Windows\Tasks\'
              - 'C:\Windows\debug\'
              - 'C:\Windows\fonts\'
              - 'C:\Windows\help\'
              - 'C:\Windows\drivers\'
              - 'C:\Windows\addins\'
              - 'C:\Windows\cursors\'
              - 'C:\Windows\system32\tasks\'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
```
