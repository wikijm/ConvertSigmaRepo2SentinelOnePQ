```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="C:\Windows\PSEXESVC.exe" and (tgt.process.user contains "AUTHORI" or tgt.process.user contains "AUTORI")))
```


# Original Sigma Rule:
```yaml
title: PsExec Service Child Process Execution as LOCAL SYSTEM
id: 7c0dcd3d-acf8-4f71-9570-f448b0034f94
related:
    - id: fa91cc36-24c9-41ce-b3c8-3bbc3f2f67ba
      type: similar
status: test
description: Detects suspicious launch of the PSEXESVC service on this system and a sub process run as LOCAL_SYSTEM (-s), which means that someone remotely started a command on this system running it with highest privileges and not only the privileges of the login user account (e.g. the administrator account)
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
author: Florian Roth (Nextron Systems)
date: 2022-07-21
modified: 2023-02-28
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: 'C:\Windows\PSEXESVC.exe'
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    condition: selection
falsepositives:
    - Users that debug Microsoft Intune issues using the commands mentioned in the official documentation; see https://learn.microsoft.com/en-us/mem/intune/apps/intune-management-extension
level: high
```
