```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "verb:sync" and tgt.process.cmdline contains "-source:RunCommand" and tgt.process.cmdline contains "-dest:runCommand") and tgt.process.image.path contains "\msdeploy.exe")) | columns ComputerName,tgt.process.user,tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Execute Files with Msdeploy.exe
id: 646bc99f-6682-4b47-a73a-17b1b64c9d34
status: test
description: Detects file execution using the msdeploy.exe lolbin
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msdeploy/
    - https://twitter.com/pabraeken/status/995837734379032576
    - https://twitter.com/pabraeken/status/999090532839313408
author: Beyu Denis, oscd.community
date: 2020-10-18
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'verb:sync'
            - '-source:RunCommand'
            - '-dest:runCommand'
        Image|endswith: '\msdeploy.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - System administrator Usage
level: medium
```
