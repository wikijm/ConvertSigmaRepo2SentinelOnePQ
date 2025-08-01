```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\SYSVOL\" and tgt.process.cmdline contains "\policies\"))
```


# Original Sigma Rule:
```yaml
title: Suspicious SYSVOL Domain Group Policy Access
id: 05f3c945-dcc8-4393-9f3d-af65077a8f86
status: test
description: Detects Access to Domain Group Policies stored in SYSVOL
references:
    - https://adsecurity.org/?p=2288
    - https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100
author: Markus Neis, Jonhnathan Ribeiro, oscd.community
date: 2018-04-09
modified: 2022-01-07
tags:
    - attack.credential-access
    - attack.t1552.006
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\SYSVOL\'
            - '\policies\'
    condition: selection
falsepositives:
    - Administrative activity
level: medium
```
