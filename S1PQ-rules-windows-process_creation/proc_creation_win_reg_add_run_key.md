```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\reg.exe" and (tgt.process.cmdline contains "reg" and tgt.process.cmdline contains " add ") and (tgt.process.cmdline contains "Software\Microsoft\Windows\CurrentVersion\Run" or tgt.process.cmdline contains "\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" or tgt.process.cmdline contains "\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")))
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
    - https://github.com/HackTricks-wiki/hacktricks/blob/e4c7b21b8f36c97c35b7c622732b38a189ce18f7/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
author: Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2021-06-28
modified: 2025-02-17
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - 'reg'
            - ' add '
        CommandLine|contains:
            - 'Software\Microsoft\Windows\CurrentVersion\Run'
            - '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
            - '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    condition: selection
falsepositives:
    - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reasons.
    - Legitimate administrator sets up autorun keys for legitimate reasons.
    - Discord
level: medium
```
