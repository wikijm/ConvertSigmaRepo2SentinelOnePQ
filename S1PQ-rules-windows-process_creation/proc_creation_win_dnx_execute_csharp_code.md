```sql
// Translated content (automatically translated on 26-09-2025 01:53:48):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\\dnx.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Application Whitelisting Bypass via Dnx.EXE
id: 81ebd28b-9607-4478-bf06-974ed9d53ed7
status: test
description: |
    Detects the execution of Dnx.EXE. The Dnx utility allows for the execution of C# code.
    Attackers might abuse this in order to bypass application whitelisting.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Csi/
    - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/
author: Beyu Denis, oscd.community
date: 2019-10-26
modified: 2024-04-24
tags:
    - attack.defense-evasion
    - attack.t1218
    - attack.t1027.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dnx.exe'
    condition: selection
falsepositives:
    - Legitimate use of dnx.exe by legitimate user
level: medium
```
