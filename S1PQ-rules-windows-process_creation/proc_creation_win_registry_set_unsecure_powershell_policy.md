```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "\ShellIds\Microsoft.PowerShell\ExecutionPolicy" or tgt.process.cmdline contains "\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy") and (tgt.process.cmdline contains "Bypass" or tgt.process.cmdline contains "RemoteSigned" or tgt.process.cmdline contains "Unrestricted")))
```


# Original Sigma Rule:
```yaml
title: Potential PowerShell Execution Policy Tampering - ProcCreation
id: cf2e938e-9a3e-4fe8-a347-411642b28a9f
related:
    - id: fad91067-08c5-4d1a-8d8c-d96a21b37814 # ProcCreation Registry
      type: similar
    - id: 87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180 # ProcCreation Cmdlet
      type: similar
    - id: 61d0475c-173f-4844-86f7-f3eebae1c66b # PowerShell ScriptBlock
      type: similar
status: test
description: Detects changes to the PowerShell execution policy registry key in order to bypass signing requirements for script execution from the CommandLine
references:
    - https://learn.microsoft.com/de-de/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.3
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-11
tags:
    - attack.defense-evasion
logsource:
    product: windows
    category: process_creation
detection:
    selection_path:
        CommandLine|contains:
            - '\ShellIds\Microsoft.PowerShell\ExecutionPolicy'
            - '\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy'
    selection_values:
        CommandLine|contains:
            - 'Bypass'
            - 'RemoteSigned'
            - 'Unrestricted'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
