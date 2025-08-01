```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "Enable-WindowsOptionalFeature" and tgt.process.cmdline contains "-Online" and tgt.process.cmdline contains "-FeatureName") and (tgt.process.cmdline contains "TelnetServer" or tgt.process.cmdline contains "Internet-Explorer-Optional-amd64" or tgt.process.cmdline contains "TFTP" or tgt.process.cmdline contains "SMB1Protocol" or tgt.process.cmdline contains "Client-ProjFS" or tgt.process.cmdline contains "Microsoft-Windows-Subsystem-Linux")))
```


# Original Sigma Rule:
```yaml
title: Potential Suspicious Windows Feature Enabled - ProcCreation
id: c740d4cf-a1e9-41de-bb16-8a46a4f57918
related:
    - id: 55c925c1-7195-426b-a136-a9396800e29b
      type: similar
status: test
description: |
    Detects usage of the built-in PowerShell cmdlet "Enable-WindowsOptionalFeature" used as a Deployment Image Servicing and Management tool.
    Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
references:
    - https://learn.microsoft.com/en-us/powershell/module/dism/enable-windowsoptionalfeature?view=windowsserver2022-ps
    - https://learn.microsoft.com/en-us/windows/win32/projfs/enabling-windows-projected-file-system
    - https://learn.microsoft.com/en-us/windows/wsl/install-on-server
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-29
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains|all:
            - 'Enable-WindowsOptionalFeature'
            - '-Online'
            - '-FeatureName'
    selection_feature:
        # Add any insecure/unusual windows features that you don't use in your environment
        CommandLine|contains:
            - 'TelnetServer'
            - 'Internet-Explorer-Optional-amd64'
            - 'TFTP'
            - 'SMB1Protocol'
            - 'Client-ProjFS'
            - 'Microsoft-Windows-Subsystem-Linux'
    condition: all of selection_*
falsepositives:
    - Legitimate usage of the features listed in the rule.
level: medium
```
