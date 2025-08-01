```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((((tgt.process.image.path contains "\schtasks.exe" and tgt.process.cmdline contains " /create ") and (tgt.process.cmdline contains ":\Perflogs" or tgt.process.cmdline contains ":\Users\All Users\" or tgt.process.cmdline contains ":\Users\Default\" or tgt.process.cmdline contains ":\Users\Public" or tgt.process.cmdline contains ":\Windows\Temp" or tgt.process.cmdline contains "\AppData\Local\" or tgt.process.cmdline contains "\AppData\Roaming\" or tgt.process.cmdline contains "%AppData%" or tgt.process.cmdline contains "%Public%")) or (src.process.cmdline contains "\svchost.exe -k netsvcs -p -s Schedule" and (tgt.process.cmdline contains ":\Perflogs" or tgt.process.cmdline contains ":\Windows\Temp" or tgt.process.cmdline contains "\Users\Public" or tgt.process.cmdline contains "%Public%"))) and (not ((src.process.cmdline contains "unattended.ini" or tgt.process.cmdline contains "update_task.xml") or tgt.process.cmdline contains "/Create /TN TVInstallRestore /TR" or (tgt.process.cmdline contains "/Create /Xml \"C:\Users\" and tgt.process.cmdline contains "\AppData\Local\Temp\.CR." and tgt.process.cmdline contains "Avira_Security_Installation.xml") or ((tgt.process.cmdline contains "/Create /F /TN" and tgt.process.cmdline contains "/Xml " and tgt.process.cmdline contains "\AppData\Local\Temp\is-" and tgt.process.cmdline contains "Avira_") and (tgt.process.cmdline contains ".tmp\UpdateFallbackTask.xml" or tgt.process.cmdline contains ".tmp\WatchdogServiceControlManagerTimeout.xml" or tgt.process.cmdline contains ".tmp\SystrayAutostart.xml" or tgt.process.cmdline contains ".tmp\MaintenanceTask.xml")) or (tgt.process.cmdline contains "\AppData\Local\Temp\" and tgt.process.cmdline contains "/Create /TN \"klcp_update\" /XML " and tgt.process.cmdline contains "\klcp_update_task.xml")))))
```


# Original Sigma Rule:
```yaml
title: Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE
id: 81325ce1-be01-4250-944f-b4789644556f
related:
    - id: 43f487f0-755f-4c2a-bce7-d6d2eec2fcf8 # TODO: Recreate after baseline
      type: derived
status: test
description: Detects Schtask creations that point to a suspicious folder or an environment variable often used by malware
references:
    - https://www.welivesecurity.com/2022/01/18/donot-go-do-not-respawn/
    - https://www.joesandbox.com/analysis/514608/0/html#324415FF7D8324231381BAD48A052F85DF04
    - https://blog.talosintelligence.com/gophish-powerrat-dcrat/
author: Florian Roth (Nextron Systems)
date: 2022-02-21
modified: 2024-10-28
tags:
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_1_create:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: ' /create '
    selection_1_all_folders:
        CommandLine|contains:
            - ':\Perflogs'
            - ':\Users\All Users\'
            - ':\Users\Default\'
            - ':\Users\Public'
            - ':\Windows\Temp'
            - '\AppData\Local\'
            - '\AppData\Roaming\'
            - '%AppData%'
            - '%Public%'
    selection_2_parent:
        ParentCommandLine|endswith: '\svchost.exe -k netsvcs -p -s Schedule'
    selection_2_some_folders:
        CommandLine|contains:
            - ':\Perflogs'
            - ':\Windows\Temp'
            - '\Users\Public'
            - '%Public%'
    filter_optional_other:
        - ParentCommandLine|contains: 'unattended.ini'
        - CommandLine|contains: 'update_task.xml'
    filter_optional_team_viewer:
        CommandLine|contains: '/Create /TN TVInstallRestore /TR'
    filter_optional_avira_install:
        # Comment out this filter if you dont use AVIRA
        CommandLine|contains|all:
            - '/Create /Xml "C:\Users\'
            - '\AppData\Local\Temp\.CR.'
            - 'Avira_Security_Installation.xml'
    filter_optional_avira_other:
        # Comment out this filter if you dont use AVIRA
        CommandLine|contains|all:
            - '/Create /F /TN'
            - '/Xml '
            - '\AppData\Local\Temp\is-'
            - 'Avira_'
        CommandLine|contains:
            - '.tmp\UpdateFallbackTask.xml'
            - '.tmp\WatchdogServiceControlManagerTimeout.xml'
            - '.tmp\SystrayAutostart.xml'
            - '.tmp\MaintenanceTask.xml'
    filter_optional_klite_codec:
        CommandLine|contains|all:
            - '\AppData\Local\Temp\'
            - '/Create /TN "klcp_update" /XML '
            - '\klcp_update_task.xml'
    condition: ( all of selection_1_* or all of selection_2_* ) and not 1 of filter_optional_*
falsepositives:
    - Benign scheduled tasks creations or executions that happen often during software installations
    - Software that uses the AppData folder and scheduled tasks to update the software in the AppData folders
level: medium
```
