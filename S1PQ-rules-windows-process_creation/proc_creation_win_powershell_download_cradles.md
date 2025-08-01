```sql
// Translated content (automatically translated on 28-07-2025 02:27:57):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains ".DownloadString(" or tgt.process.cmdline contains ".DownloadFile(" or tgt.process.cmdline contains "Invoke-WebRequest " or tgt.process.cmdline contains "iwr "))
```


# Original Sigma Rule:
```yaml
title: PowerShell Web Download
id: 6e897651-f157-4d8f-aaeb-df8151488385
status: test
description: Detects suspicious ways to download files or content using PowerShell
references:
    - https://github.com/VirtualAlllocEx/Payload-Download-Cradles/blob/88e8eca34464a547c90d9140d70e9866dcbc6a12/Download-Cradles.cmd
author: Florian Roth (Nextron Systems)
date: 2022-03-24
modified: 2023-01-05
tags:
    - attack.command-and-control
    - attack.execution
    - attack.t1059.001
    - attack.t1105
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '.DownloadString('
            - '.DownloadFile('
            - 'Invoke-WebRequest '
            - 'iwr '
    condition: selection
falsepositives:
    - Scripts or tools that download files
level: medium
```
