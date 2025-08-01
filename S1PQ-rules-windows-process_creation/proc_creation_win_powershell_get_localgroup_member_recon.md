```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Get-LocalGroupMember " and (tgt.process.cmdline contains "domain admins" or tgt.process.cmdline contains " administrator" or tgt.process.cmdline contains " administrateur" or tgt.process.cmdline contains "enterprise admins" or tgt.process.cmdline contains "Exchange Trusted Subsystem" or tgt.process.cmdline contains "Remote Desktop Users" or tgt.process.cmdline contains "Utilisateurs du Bureau à distance" or tgt.process.cmdline contains "Usuarios de escritorio remoto"))) | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet
id: c8a180d6-47a3-4345-a609-53f9c3d834fc
related:
    - id: cef24b90-dddc-4ae1-a09a-8764872f69fc
      type: similar
status: test
description: Detects suspicious reconnaissance command line activity on Windows systems using the PowerShell Get-LocalGroupMember Cmdlet
references:
    - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-10
tags:
    - attack.discovery
    - attack.t1087.001
logsource:
    category: process_creation
    product: windows
detection:
    # Covers group and localgroup flags
    selection_cmdlet:
        CommandLine|contains: 'Get-LocalGroupMember '
    selection_group:
        CommandLine|contains:
            # Add more groups for other languages
            - 'domain admins'
            - ' administrator' # Typo without an 'S' so we catch both
            - ' administrateur' # Typo without an 'S' so we catch both
            - 'enterprise admins'
            - 'Exchange Trusted Subsystem'
            - 'Remote Desktop Users'
            - 'Utilisateurs du Bureau à distance' # French for "Remote Desktop Users"
            - 'Usuarios de escritorio remoto' # Spanish for "Remote Desktop Users"
    condition: all of selection_*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: medium
```
