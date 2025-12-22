```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\powershell.exe" or src.process.image.path contains "\\pwsh.exe") and src.process.cmdline contains "\\WindowsPowerShell\\Modules\\Pester\\") and (src.process.cmdline contains "{ Invoke-Pester -EnableExit ;" or src.process.cmdline contains "{ Get-Help \"")))
```


# Original Sigma Rule:
```yaml
title: Execute Code with Pester.bat as Parent
id: 18988e1b-9087-4f8a-82fe-0414dce49878
related:
    - id: 59e938ff-0d6d-4dc3-b13f-36cc28734d4e
      type: similar
status: test
description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
references:
    - https://twitter.com/Oddvarmoe/status/993383596244258816
    - https://twitter.com/_st0pp3r_/status/1560072680887525378
author: frack113, Nasreddine Bencherchali
date: 2022-08-20
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense-evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection_module:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        ParentCommandLine|contains: '\WindowsPowerShell\Modules\Pester\'
    selection_cli:
        ParentCommandLine|contains:
            - '{ Invoke-Pester -EnableExit ;'
            - '{ Get-Help "'
    condition: all of selection_*
falsepositives:
    - Legitimate use of Pester for writing tests for Powershell scripts and modules
level: medium
```
