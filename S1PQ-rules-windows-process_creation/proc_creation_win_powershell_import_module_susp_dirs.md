```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Import-Module \"$Env:Temp\" or tgt.process.cmdline contains "Import-Module '$Env:Temp\" or tgt.process.cmdline contains "Import-Module $Env:Temp\" or tgt.process.cmdline contains "Import-Module \"$Env:Appdata\" or tgt.process.cmdline contains "Import-Module '$Env:Appdata\" or tgt.process.cmdline contains "Import-Module $Env:Appdata\" or tgt.process.cmdline contains "Import-Module C:\Users\Public\" or tgt.process.cmdline contains "ipmo \"$Env:Temp\" or tgt.process.cmdline contains "ipmo '$Env:Temp\" or tgt.process.cmdline contains "ipmo $Env:Temp\" or tgt.process.cmdline contains "ipmo \"$Env:Appdata\" or tgt.process.cmdline contains "ipmo '$Env:Appdata\" or tgt.process.cmdline contains "ipmo $Env:Appdata\" or tgt.process.cmdline contains "ipmo C:\Users\Public\"))
```


# Original Sigma Rule:
```yaml
title: Import PowerShell Modules From Suspicious Directories - ProcCreation
id: c31364f7-8be6-4b77-8483-dd2b5a7b69a3
related:
    - id: 21f9162c-5f5d-4b01-89a8-b705bd7d10ab
      type: similar
status: test
description: Detects powershell scripts that import modules from suspicious directories
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-10
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Import-Module "$Env:Temp\'
            - Import-Module '$Env:Temp\
            - 'Import-Module $Env:Temp\'
            - 'Import-Module "$Env:Appdata\'
            - Import-Module '$Env:Appdata\
            - 'Import-Module $Env:Appdata\'
            - 'Import-Module C:\Users\Public\'
            # Import-Module alias is "ipmo"
            - 'ipmo "$Env:Temp\'
            - ipmo '$Env:Temp\
            - 'ipmo $Env:Temp\'
            - 'ipmo "$Env:Appdata\'
            - ipmo '$Env:Appdata\
            - 'ipmo $Env:Appdata\'
            - 'ipmo C:\Users\Public\'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
