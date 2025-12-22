```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\OpenWith.exe" and tgt.process.cmdline contains "/c"))
```


# Original Sigma Rule:
```yaml
title: OpenWith.exe Executes Specified Binary
id: cec8e918-30f7-4e2d-9bfa-a59cc97ae60f
status: test
description: The OpenWith.exe executes other binary
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/4db780e0f0b2e2bb8cb1fa13e09196da9b9f1834/yml/LOLUtilz/OSBinaries/Openwith.yml
    - https://twitter.com/harr0ey/status/991670870384021504
author: Beyu Denis, oscd.community (rule), @harr0ey (idea)
date: 2019-10-12
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\OpenWith.exe'
        CommandLine|contains: '/c'
    condition: selection
falsepositives:
    - Unknown
level: high
```
