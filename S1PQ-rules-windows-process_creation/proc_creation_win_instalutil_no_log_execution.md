```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\InstallUtil.exe" and tgt.process.image.path contains "Microsoft.NET\\Framework" and (tgt.process.cmdline contains "/logfile= " and tgt.process.cmdline contains "/LogToConsole=false")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Execution of InstallUtil Without Log
id: d042284c-a296-4988-9be5-f424fadcc28c
status: test
description: Uses the .NET InstallUtil.exe application in order to execute image without log
references:
    - https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/
    - https://learn.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool
author: frack113
date: 2022-01-23
modified: 2022-02-04
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\InstallUtil.exe'
        Image|contains: 'Microsoft.NET\Framework'
        CommandLine|contains|all:
            - '/logfile= '
            - '/LogToConsole=false'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
