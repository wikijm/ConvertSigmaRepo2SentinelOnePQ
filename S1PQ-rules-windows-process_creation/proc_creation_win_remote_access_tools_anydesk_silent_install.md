```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "--install" and tgt.process.cmdline contains "--start-with-win" and tgt.process.cmdline contains "--silent")) | columns tgt.process.cmdline,src.process.cmdline,tgt.process.image.path
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - AnyDesk Silent Installation
id: 114e7f1c-f137-48c8-8f54-3088c24ce4b9
status: test
description: Detects AnyDesk Remote Desktop silent installation. Which can be used by attackers to gain remote access.
references:
    - https://twitter.com/TheDFIRReport/status/1423361119926816776?s=20
    - https://support.anydesk.com/Automatic_Deployment
author: Ján Trenčanský
date: 2021-08-06
modified: 2023-03-05
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '--install'
            - '--start-with-win'
            - '--silent'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
    - CurrentDirectory
falsepositives:
    - Legitimate deployment of AnyDesk
level: high
```
