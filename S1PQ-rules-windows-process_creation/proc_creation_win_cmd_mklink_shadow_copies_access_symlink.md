```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "mklink" and tgt.process.cmdline contains "HarddiskVolumeShadowCopy"))
```


# Original Sigma Rule:
```yaml
title: VolumeShadowCopy Symlink Creation Via Mklink
id: 40b19fa6-d835-400c-b301-41f3a2baacaf
status: stable
description: Shadow Copies storage symbolic link creation using operating systems utilities
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
author: Teymur Kheirkhabarov, oscd.community
date: 2019-10-22
modified: 2023-03-06
tags:
    - attack.credential-access
    - attack.t1003.002
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'mklink'
            - 'HarddiskVolumeShadowCopy'
    condition: selection
falsepositives:
    - Legitimate administrator working with shadow copies, access for backup purposes
level: high
```
