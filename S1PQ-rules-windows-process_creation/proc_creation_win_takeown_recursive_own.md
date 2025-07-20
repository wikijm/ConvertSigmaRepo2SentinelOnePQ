```sql
// Translated content (automatically translated on 20-07-2025 02:30:22):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\takeown.exe" and (tgt.process.cmdline contains "/f " and tgt.process.cmdline contains "/r"))) | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Suspicious Recursive Takeown
id: 554601fb-9b71-4bcc-abf4-21a611be4fde
status: test
description: Adversaries can interact with the DACLs using built-in Windows commands takeown which can grant adversaries higher permissions on specific files and folders
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.001/T1222.001.md#atomic-test-1---take-ownership-using-takeown-utility
author: frack113
date: 2022-01-30
modified: 2022-11-21
tags:
    - attack.defense-evasion
    - attack.t1222.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\takeown.exe'
        CommandLine|contains|all:
            - '/f '
            - '/r'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Scripts created by developers and admins
    - Administrative activity
level: medium
```
