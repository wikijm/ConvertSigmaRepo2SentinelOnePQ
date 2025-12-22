```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe") and (tgt.process.cmdline contains " | iex;" or tgt.process.cmdline contains " | iex " or tgt.process.cmdline contains " | iex}" or tgt.process.cmdline contains " | IEX ;" or tgt.process.cmdline contains " | IEX -Error" or tgt.process.cmdline contains " | IEX (new" or tgt.process.cmdline contains ");IEX ")) and (tgt.process.cmdline contains "::FromBase64String" or tgt.process.cmdline contains ".GetString([System.Convert]::")) or (tgt.process.cmdline contains ")|iex;$" or tgt.process.cmdline contains ");iex($" or tgt.process.cmdline contains ");iex $" or tgt.process.cmdline contains " | IEX | " or tgt.process.cmdline contains " | iex\\\"")))
```


# Original Sigma Rule:
```yaml
title: Suspicious PowerShell IEX Execution Patterns
id: 09576804-7a05-458e-a817-eb718ca91f54
status: test
description: Detects suspicious ways to run Invoke-Execution using IEX alias
references:
    - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-03-24
modified: 2022-11-28
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_combined_1:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - ' | iex;'
            - ' | iex '
            - ' | iex}'
            - ' | IEX ;'
            - ' | IEX -Error'
            - ' | IEX (new'
            - ');IEX '
    selection_combined_2:
        CommandLine|contains:
            - '::FromBase64String'
            - '.GetString([System.Convert]::'
    selection_standalone:
        CommandLine|contains:
            - ')|iex;$'
            - ');iex($'
            - ');iex $'
            - ' | IEX | '
            - ' | iex\"'
    condition: all of selection_combined_* or selection_standalone
falsepositives:
    - Legitimate scripts that use IEX
level: high
```
