```sql
// Translated content (automatically translated on 12-05-2025 02:05:52):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "reg" and tgt.process.cmdline contains " ADD " and tgt.process.cmdline contains "Software\Microsoft\Windows\CurrentVersion\Run"))
```


# Original Sigma Rule:
```yaml
title: Potential Persistence Attempt Via Run Keys Using Reg.EXE
id: de587dce-915e-4218-aac4-835ca6af6f70
status: test
description: Detects suspicious command line reg.exe tool adding key to RUN key in Registry
references:
    - https://app.any.run/tasks/9c0f37bc-867a-4314-b685-e101566766d7/
    - https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
author: Florian Roth (Nextron Systems)
date: 2021-06-28
modified: 2023-01-30
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'reg'
            - ' ADD '
            - 'Software\Microsoft\Windows\CurrentVersion\Run'
    condition: selection
falsepositives:
    - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reasons.
    - Legitimate administrator sets up autorun keys for legitimate reasons.
    - Discord
level: medium
```
