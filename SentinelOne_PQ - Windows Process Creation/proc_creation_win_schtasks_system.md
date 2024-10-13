```sql
// Translated content (automatically translated on 13-10-2024 01:24:17):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\schtasks.exe" and (tgt.process.cmdline contains " /change " or tgt.process.cmdline contains " /create ")) and tgt.process.cmdline contains "/ru " and (tgt.process.cmdline contains "NT AUT" or tgt.process.cmdline contains " SYSTEM ")) and (not ((tgt.process.image.path contains "\schtasks.exe" and (tgt.process.cmdline contains "/TN TVInstallRestore" and tgt.process.cmdline contains "\TeamViewer_.exe")) or (tgt.process.cmdline contains "/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR " or tgt.process.cmdline contains ":\Program Files (x86)\Avira\System Speedup\setup\avira_speedup_setup.exe" or tgt.process.cmdline contains "/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART\" /RL HIGHEST")))))
```


# Original Sigma Rule:
```yaml
title: Schtasks Creation Or Modification With SYSTEM Privileges
id: 89ca78fd-b37c-4310-b3d3-81a023f83936
status: test
description: Detects the creation or update of a scheduled task to run with "NT AUTHORITY\SYSTEM" privileges
references:
    - https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-28
modified: 2023-10-11
tags:
    - attack.execution
    - attack.persistence
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_root:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - ' /change '
            - ' /create '
    selection_run:
        CommandLine|contains: '/ru '
    selection_user:
        CommandLine|contains:
            - 'NT AUT' # This covers the usual NT AUTHORITY\SYSTEM
            - ' SYSTEM ' # SYSTEM is a valid value for schtasks hence it gets it's own value with space
    filter_optional_teamviewer:
        # FP from test set in SIGMA
        # Cannot use ParentImage on all OSes for 4688 events
        # ParentImage|contains|all:
        #     - '\AppData\Local\Temp\'
        #     - 'TeamViewer_.exe'
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/TN TVInstallRestore'
            - '\TeamViewer_.exe'
    filter_optional_avira:
        CommandLine|contains:
            - '/Create /F /RU System /SC WEEKLY /TN AviraSystemSpeedupVerify /TR '
            - ':\Program Files (x86)\Avira\System Speedup\setup\avira_speedup_setup.exe'
            - '/VERIFY /VERYSILENT /NOSTART /NODOTNET /NORESTART" /RL HIGHEST'
    condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: high
```
