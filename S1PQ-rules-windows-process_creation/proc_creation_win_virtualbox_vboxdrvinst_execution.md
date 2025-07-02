```sql
// Translated content (automatically translated on 02-07-2025 02:07:36):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\VBoxDrvInst.exe" and (tgt.process.cmdline contains "driver" and tgt.process.cmdline contains "executeinf"))) | columns ComputerName,tgt.process.user,tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Suspicious VBoxDrvInst.exe Parameters
id: b7b19cb6-9b32-4fc4-a108-73f19acfe262
status: test
description: |
  Detect VBoxDrvInst.exe run with parameters allowing processing INF file.
  This allows to create values in the registry and install drivers.
  For example one could use this technique to obtain persistence via modifying one of Run or RunOnce registry keys
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/4db780e0f0b2e2bb8cb1fa13e09196da9b9f1834/yml/LOLUtilz/OtherBinaries/VBoxDrvInst.yml
    - https://twitter.com/pabraeken/status/993497996179492864
author: Konstantin Grishchenko, oscd.community
date: 2020-10-06
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\VBoxDrvInst.exe'
        CommandLine|contains|all:
            - 'driver'
            - 'executeinf'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate use of VBoxDrvInst.exe utility by VirtualBox Guest Additions installation process
level: medium
```
