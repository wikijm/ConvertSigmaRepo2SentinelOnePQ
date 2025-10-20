```sql
// Translated content (automatically translated on 20-10-2025 02:04:56):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\cmd.exe" and (tgt.process.cmdline contains " /c" and tgt.process.cmdline contains "dir " and tgt.process.cmdline contains "\\Users\\")) and (not tgt.process.cmdline contains " rmdir ")) or (((tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe") and tgt.process.cmdline contains "user") and (not (tgt.process.cmdline contains "/domain" or tgt.process.cmdline contains "/add" or tgt.process.cmdline contains "/delete" or tgt.process.cmdline contains "/active" or tgt.process.cmdline contains "/expires" or tgt.process.cmdline contains "/passwordreq" or tgt.process.cmdline contains "/scriptpath" or tgt.process.cmdline contains "/times" or tgt.process.cmdline contains "/workstations"))) or ((tgt.process.image.path contains "\\whoami.exe" or tgt.process.image.path contains "\\quser.exe" or tgt.process.image.path contains "\\qwinsta.exe") or (tgt.process.image.path contains "\\wmic.exe" and (tgt.process.cmdline contains "useraccount" and tgt.process.cmdline contains "get")) or (tgt.process.image.path contains "\\cmdkey.exe" and tgt.process.cmdline contains " /l"))))
```


# Original Sigma Rule:
```yaml
title: Local Accounts Discovery
id: 502b42de-4306-40b4-9596-6f590c81f073
status: test
description: Local accounts, System Owner/User discovery using operating systems utilities
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1033/T1033.md
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2019-10-21
modified: 2023-01-03
tags:
    - attack.discovery
    - attack.t1033
    - attack.t1087.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_other_img:
        Image|endswith:
            - '\whoami.exe'
            - '\quser.exe'
            - '\qwinsta.exe'
    selection_other_wmi:
        Image|endswith: '\wmic.exe'
        CommandLine|contains|all:
            - 'useraccount'
            - 'get'
    selection_other_cmdkey:
        Image|endswith: '\cmdkey.exe'
        CommandLine|contains: ' /l'
    selection_cmd:
        Image|endswith: '\cmd.exe'
        CommandLine|contains|all:
            - ' /c'
            - 'dir '
            - '\Users\'
    filter_cmd:
        CommandLine|contains: ' rmdir ' # don't match on 'dir'   "C:\Windows\System32\cmd.exe" /q /c rmdir /s /q "C:\Users\XX\AppData\Local\Microsoft\OneDrive\19.232.1124.0005"
    selection_net:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'user'
    filter_net:
        CommandLine|contains:
            - '/domain'       # local account discovery only
            - '/add'          # discovery only
            - '/delete'       # discovery only
            - '/active'       # discovery only
            - '/expires'      # discovery only
            - '/passwordreq'  # discovery only
            - '/scriptpath'   # discovery only
            - '/times'        # discovery only
            - '/workstations' # discovery only
    condition: (selection_cmd and not filter_cmd) or (selection_net and not filter_net) or 1 of selection_other_*
falsepositives:
    - Legitimate administrator or user enumerates local users for legitimate reason
level: low
```
