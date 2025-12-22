```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Win32_NTEventlogFile" and (tgt.process.cmdline contains ".BackupEventlog(" or tgt.process.cmdline contains ".ChangeSecurityPermissions(" or tgt.process.cmdline contains ".ChangeSecurityPermissionsEx(" or tgt.process.cmdline contains ".ClearEventLog(" or tgt.process.cmdline contains ".Delete(" or tgt.process.cmdline contains ".DeleteEx(" or tgt.process.cmdline contains ".Rename(" or tgt.process.cmdline contains ".TakeOwnerShip(" or tgt.process.cmdline contains ".TakeOwnerShipEx(")))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Call To Win32_NTEventlogFile Class
id: caf201a9-c2ce-4a26-9c3a-2b9525413711
related:
    - id: e2812b49-bae0-4b21-b366-7c142eafcde2
      type: similar
status: test
description: Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script
references:
    - https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394225(v=vs.85)
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-07-13
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_class:
        CommandLine|contains: 'Win32_NTEventlogFile'
    selection_function:
        CommandLine|contains:
            - '.BackupEventlog('
            - '.ChangeSecurityPermissions('
            - '.ChangeSecurityPermissionsEx('
            - '.ClearEventLog('
            - '.Delete('
            - '.DeleteEx('
            - '.Rename('
            - '.TakeOwnerShip('
            - '.TakeOwnerShipEx('
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
