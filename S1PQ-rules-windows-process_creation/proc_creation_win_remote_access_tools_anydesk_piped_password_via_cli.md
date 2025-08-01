```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "/c " and tgt.process.cmdline contains "echo " and tgt.process.cmdline contains ".exe --set-password"))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - AnyDesk Piped Password Via CLI
id: b1377339-fda6-477a-b455-ac0923f9ec2c
status: test
description: Detects piping the password to an anydesk instance via CMD and the '--set-password' flag.
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-28
modified: 2023-03-05
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            # Example: C:\WINDOWS\system32\cmd.exe /C cmd.exe /c echo J9kzQ2Y0qO |C:\ProgramData\anydesk.exe --set-password
            - '/c '
            - 'echo '
            - '.exe --set-password'
    condition: selection
falsepositives:
    - Legitimate piping of the password to anydesk
    - Some FP could occur with similar tools that uses the same command line '--set-password'
level: medium
```
