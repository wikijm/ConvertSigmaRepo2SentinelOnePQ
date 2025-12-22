```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\devtoolslauncher.exe" and tgt.process.cmdline contains "LaunchForDeploy"))
```


# Original Sigma Rule:
```yaml
title: Devtoolslauncher.exe Executes Specified Binary
id: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
status: test
description: The Devtoolslauncher.exe executes other binary
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Devtoolslauncher/
    - https://twitter.com/_felamos/status/1179811992841797632
author: Beyu Denis, oscd.community (rule), @_felamos (idea)
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
        Image|endswith: '\devtoolslauncher.exe'
        CommandLine|contains: 'LaunchForDeploy'
    condition: selection
falsepositives:
    - Legitimate use of devtoolslauncher.exe by legitimate user
level: high
```
