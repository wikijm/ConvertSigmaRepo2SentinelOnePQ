```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\schtasks.exe" and tgt.process.cmdline contains "/Create ") and (((tgt.process.cmdline contains "/sc minute " or tgt.process.cmdline contains "/ru system ") and (tgt.process.cmdline contains "cmd /c" or tgt.process.cmdline contains "cmd /k" or tgt.process.cmdline contains "cmd /r" or tgt.process.cmdline contains "cmd.exe /c " or tgt.process.cmdline contains "cmd.exe /k " or tgt.process.cmdline contains "cmd.exe /r ")) or (tgt.process.cmdline contains " -decode " or tgt.process.cmdline contains " -enc " or tgt.process.cmdline contains " -w hidden " or tgt.process.cmdline contains " bypass " or tgt.process.cmdline contains " IEX" or tgt.process.cmdline contains ".DownloadData" or tgt.process.cmdline contains ".DownloadFile" or tgt.process.cmdline contains ".DownloadString" or tgt.process.cmdline contains "/c start /min " or tgt.process.cmdline contains "FromBase64String" or tgt.process.cmdline contains "mshta http" or tgt.process.cmdline contains "mshta.exe http") or ((tgt.process.cmdline contains ":\\ProgramData\\" or tgt.process.cmdline contains ":\\Temp\\" or tgt.process.cmdline contains ":\\Tmp\\" or tgt.process.cmdline contains ":\\Users\\Public\\" or tgt.process.cmdline contains ":\\Windows\\Temp\\" or tgt.process.cmdline contains "\\AppData\\" or tgt.process.cmdline contains "%AppData%" or tgt.process.cmdline contains "%Temp%" or tgt.process.cmdline contains "%tmp%") and (tgt.process.cmdline contains "cscript" or tgt.process.cmdline contains "curl" or tgt.process.cmdline contains "wscript")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Command Patterns In Scheduled Task Creation
id: f2c64357-b1d2-41b7-849f-34d2682c0fad
status: test
description: Detects scheduled task creation using "schtasks" that contain potentially suspicious or uncommon commands
references:
    - https://app.any.run/tasks/512c1352-6380-4436-b27d-bb62f0c020d6/
    - https://twitter.com/RedDrip7/status/1506480588827467785
    - https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/devil-bait/NCSC-MAR-Devil-Bait.pdf
author: Florian Roth (Nextron Systems)
date: 2022-02-23
modified: 2024-03-19
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/Create '
    selection_pattern_1:
        CommandLine|contains:
            - '/sc minute '
            - '/ru system '
    selection_pattern_2:
        CommandLine|contains:
            - 'cmd /c'
            - 'cmd /k'
            - 'cmd /r'
            - 'cmd.exe /c '
            - 'cmd.exe /k '
            - 'cmd.exe /r '
    selection_uncommon:
        CommandLine|contains:
            - ' -decode '
            - ' -enc '
            - ' -w hidden '
            - ' bypass '
            - ' IEX'
            - '.DownloadData'
            - '.DownloadFile'
            - '.DownloadString'
            - '/c start /min ' # https://twitter.com/RedDrip7/status/1506480588827467785
            - 'FromBase64String'
            - 'mshta http'
            - 'mshta.exe http'
    selection_anomaly_1:
        CommandLine|contains:
            - ':\ProgramData\'
            - ':\Temp\'
            - ':\Tmp\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\AppData\'
            - '%AppData%'
            - '%Temp%'
            - '%tmp%'
    selection_anomaly_2:
        CommandLine|contains:
            - 'cscript'
            - 'curl'
            - 'wscript'
    condition: selection_schtasks and ( all of selection_pattern_* or selection_uncommon or all of selection_anomaly_* )
falsepositives:
    - Software installers that run from temporary folders and also install scheduled tasks are expected to generate some false positives
level: high
```
