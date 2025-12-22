```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\powershell.exe" or src.process.image.path contains "\\pwsh.exe") and (tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe") and (tgt.process.cmdline contains "Get-Content" and tgt.process.cmdline contains "-Stream")))
```


# Original Sigma Rule:
```yaml
title: Run PowerShell Script from ADS
id: 45a594aa-1fbd-4972-a809-ff5a99dd81b8
status: test
description: Detects PowerShell script execution from Alternate Data Stream (ADS)
references:
    - https://github.com/p0shkatz/Get-ADS/blob/1c3a3562e713c254edce1995a7d9879c687c7473/Get-ADS.ps1
author: Sergey Soldatov, Kaspersky Lab, oscd.community
date: 2019-10-30
modified: 2022-07-14
tags:
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Get-Content'
            - '-Stream'
    condition: selection
falsepositives:
    - Unknown
level: high
```
