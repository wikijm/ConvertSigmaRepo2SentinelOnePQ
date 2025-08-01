```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\reg.exe" and tgt.process.cmdline contains "add") and (tgt.process.cmdline contains "\software\Microsoft\Windows\CurrentVersion\Run" or tgt.process.cmdline contains "\software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" or tgt.process.cmdline contains "\software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" or tgt.process.cmdline contains "\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" or tgt.process.cmdline contains "\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" or tgt.process.cmdline contains "\software\Microsoft\Windows NT\CurrentVersion\Windows" or tgt.process.cmdline contains "\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" or tgt.process.cmdline contains "\system\CurrentControlSet\Control\SafeBoot\AlternateShell"))) | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Direct Autorun Keys Modification
id: 24357373-078f-44ed-9ac4-6d334a668a11
status: test
description: Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
    - https://github.com/HackTricks-wiki/hacktricks/blob/e4c7b21b8f36c97c35b7c622732b38a189ce18f7/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
author: Victor Sergeev, Daniil Yugoslavskiy, oscd.community, Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2019-10-25
modified: 2025-02-17
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\reg.exe'
        CommandLine|contains: 'add'     # to avoid intersection with discovery tactic rules
    selection_2:
        CommandLine|contains:           # need to improve this list, there are plenty of ASEP reg keys
            - '\software\Microsoft\Windows\CurrentVersion\Run' # Also covers the strings "RunOnce", "RunOnceEx", "RunServices", "RunServicesOnce"
            - '\software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
            - '\software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
            - '\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit'
            - '\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell'
            - '\software\Microsoft\Windows NT\CurrentVersion\Windows'
            - '\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
            - '\system\CurrentControlSet\Control\SafeBoot\AlternateShell'
    condition: all of selection_*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reasons.
    - Legitimate administrator sets up autorun keys for legitimate reasons.
    - Discord
level: medium
```
