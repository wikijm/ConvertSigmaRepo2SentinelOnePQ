```sql
// Translated content (automatically translated on 23-09-2025 01:52:14):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\ruby.exe" and (tgt.process.cmdline contains "-i " and tgt.process.cmdline contains "-u " and tgt.process.cmdline contains "-p ")))
```


# Original Sigma Rule:
```yaml
title: HackTool - WinRM Access Via Evil-WinRM
id: a197e378-d31b-41c0-9635-cfdf1c1bb423
status: test
description: Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.006/T1021.006.md#atomic-test-3---winrm-access-with-evil-winrm
    - https://github.com/Hackplayers/evil-winrm
author: frack113
date: 2022-01-07
modified: 2023-02-13
tags:
    - attack.lateral-movement
    - attack.t1021.006
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ruby.exe'
        CommandLine|contains|all:
            - '-i '
            - '-u '
            - '-p '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
