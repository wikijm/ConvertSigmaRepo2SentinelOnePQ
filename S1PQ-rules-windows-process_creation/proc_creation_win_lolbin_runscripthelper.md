```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\Runscripthelper.exe" and tgt.process.cmdline contains "surfacecheck"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Runscripthelper.exe
id: eca49c87-8a75-4f13-9c73-a5a29e845f03
status: test
description: Detects execution of powershell scripts via Runscripthelper.exe
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Runscripthelper/
author: Victor Sergeev, oscd.community
date: 2020-10-09
modified: 2022-07-11
tags:
    - attack.execution
    - attack.t1059
    - attack.defense-evasion
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Runscripthelper.exe'
        CommandLine|contains: 'surfacecheck'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
