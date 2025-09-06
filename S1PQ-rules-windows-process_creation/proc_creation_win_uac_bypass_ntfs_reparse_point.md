```sql
// Translated content (automatically translated on 06-09-2025 01:50:31):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "\"C:\\Windows\\system32\\wusa.exe\"  /quiet C:\\Users\\" and tgt.process.cmdline contains "\\AppData\\Local\\Temp\\update.msu" and (tgt.process.integrityLevel in ("High","System","S-1-16-16384","S-1-16-12288"))) or (src.process.cmdline="\"C:\\Windows\\system32\\dism.exe\" /online /quiet /norestart /add-package /packagepath:\"C:\\Windows\\system32\\pe386\" /ignorecheck" and (tgt.process.integrityLevel in ("High","System")) and (tgt.process.cmdline contains "C:\\Users\\" and tgt.process.cmdline contains "\\AppData\\Local\\Temp\\" and tgt.process.cmdline contains "\\dismhost.exe {") and tgt.process.image.path contains "\\DismHost.exe")))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using NTFS Reparse Point - Process
id: 39ed3c80-e6a1-431b-9df3-911ac53d08a7
status: test
description: Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-30
modified: 2024-12-01
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|startswith: '"C:\Windows\system32\wusa.exe"  /quiet C:\Users\'
        CommandLine|endswith: '\AppData\Local\Temp\update.msu'
        IntegrityLevel:
            - 'High'
            - 'System'
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
    selection2:
        ParentCommandLine: '"C:\Windows\system32\dism.exe" /online /quiet /norestart /add-package /packagepath:"C:\Windows\system32\pe386" /ignorecheck'
        IntegrityLevel:
            - 'High'
            - 'System'
        CommandLine|contains|all:
            - 'C:\Users\'
            - '\AppData\Local\Temp\'
            - '\dismhost.exe {'
        Image|endswith: '\DismHost.exe'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
