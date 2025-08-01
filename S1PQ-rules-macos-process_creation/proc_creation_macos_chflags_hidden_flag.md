```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/chflags" and tgt.process.cmdline contains "hidden "))
```


# Original Sigma Rule:
```yaml
title: Hidden Flag Set On File/Directory Via Chflags - MacOS
id: 3b2c1059-ae5f-40b6-b5d4-6106d3ac20fe
status: test
description: |
    Detects the execution of the "chflags" utility with the "hidden" flag, in order to hide files on MacOS.
    When a file or directory has this hidden flag set, it becomes invisible to the default file listing commands and in graphical file browsers.
references:
    - https://www.sentinelone.com/labs/apt32-multi-stage-macos-trojan-innovates-on-crimeware-scripting-technique/
    - https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/
    - https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/Unit_42/unit42-wirelurker.pdf
    - https://ss64.com/mac/chflags.html
author: Omar Khaled (@beacon_exe)
date: 2024-08-21
tags:
    - attack.defense-evasion
    - attack.credential-access
    - attack.command-and-control
    - attack.t1218
    - attack.t1564.004
    - attack.t1552.001
    - attack.t1105
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: '/chflags'
        CommandLine|contains: 'hidden '
    condition: selection
falsepositives:
    - Legitimate usage of chflags by administrators and users.
level: medium
```
