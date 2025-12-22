```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\code.exe" and ((tgt.process.image.path contains "\\calc.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\wscript.exe") or ((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\cmd.exe") and (tgt.process.cmdline contains "Invoke-Expressions" or tgt.process.cmdline contains "IEX" or tgt.process.cmdline contains "Invoke-Command" or tgt.process.cmdline contains "ICM" or tgt.process.cmdline contains "DownloadString" or tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "regsvr32" or tgt.process.cmdline contains "wscript" or tgt.process.cmdline contains "cscript")) or (tgt.process.image.path contains ":\\Users\\Public\\" or tgt.process.image.path contains ":\\Windows\\Temp\\" or tgt.process.image.path contains ":\\Temp\\"))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Child Process Of VsCode
id: 5a3164f2-b373-4152-93cf-090b13c12d27
status: test
description: Detects uncommon or suspicious child processes spawning from a VsCode "code.exe" process. This could indicate an attempt of persistence via VsCode tasks or terminal profiles.
references:
    - https://twitter.com/nas_bench/status/1618021838407495681
    - https://twitter.com/nas_bench/status/1618021415852335105
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-26
modified: 2023-10-25
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\code.exe'
    selection_children_images:
        Image|endswith:
            - '\calc.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\cscript.exe'
            - '\wscript.exe'
    selection_children_cli:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
        CommandLine|contains:
            - 'Invoke-Expressions'
            - 'IEX'
            - 'Invoke-Command'
            - 'ICM'
            - 'DownloadString'
            - 'rundll32'
            - 'regsvr32'
            - 'wscript'
            - 'cscript'
    selection_children_paths:
        Image|contains:
            # Add more suspicious locations
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - ':\Temp\'
    condition: selection_parent and 1 of selection_children_*
falsepositives:
    - In development environment where VsCode is used heavily. False positives may occur when developers use task to compile or execute different types of code. Remove or add processes accordingly
level: medium
```
