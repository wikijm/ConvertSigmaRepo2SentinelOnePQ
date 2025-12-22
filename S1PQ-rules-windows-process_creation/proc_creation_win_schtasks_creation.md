```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\schtasks.exe" and tgt.process.cmdline contains " /create ") and (not (tgt.process.user contains "AUTHORI" or tgt.process.user contains "AUTORI")) and (not ((src.process.image.path in ("C:\\Program Files\\Microsoft Office\\root\\integration\\integrator.exe","C:\\Program Files (x86)\\Microsoft Office\\root\\integration\\integrator.exe")) and (tgt.process.image.path in ("C:\\Windows\\System32\\schtasks.exe","C:\\Windows\\SysWOW64\\schtasks.exe")) and tgt.process.cmdline contains "Microsoft\\Office\\Office Performance Monitor"))))
```


# Original Sigma Rule:
```yaml
title: Scheduled Task Creation Via Schtasks.EXE
id: 92626ddd-662c-49e3-ac59-f6535f12d189
status: test
description: Detects the creation of scheduled tasks by user accounts via the "schtasks" utility.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
author: Florian Roth (Nextron Systems)
date: 2019-01-16
modified: 2025-10-22
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1053.005
    - attack.s0111
    - car.2013-08-001
    - stp.1u
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: ' /create '
    filter_main_system_user:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    filter_optional_msoffice:
        #  schtasks.exe /Create /tn "Microsoft\Office\Office Performance Monitor" /XML "C:\ProgramData\Microsoft\ClickToRun\{9AC08E99-230B-47e8-9721-4577B7F124EA}\Microsoft_Office_Office Performance Monitor.xml"
        ParentImage:
            - 'C:\Program Files\Microsoft Office\root\integration\integrator.exe'
            - 'C:\Program Files (x86)\Microsoft Office\root\integration\integrator.exe'
        Image:
            - 'C:\Windows\System32\schtasks.exe'
            - 'C:\Windows\SysWOW64\schtasks.exe'
        CommandLine|contains: 'Microsoft\Office\Office Performance Monitor'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Administrative activity
    - Software installation
level: low
```
