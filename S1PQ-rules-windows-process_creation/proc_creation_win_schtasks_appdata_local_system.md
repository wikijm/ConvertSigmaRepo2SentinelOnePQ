```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\schtasks.exe" and (tgt.process.cmdline contains "/Create" and tgt.process.cmdline contains "/RU" and tgt.process.cmdline contains "/TR" and tgt.process.cmdline contains "C:\\Users\\" and tgt.process.cmdline contains "\\AppData\\Local\\") and (tgt.process.cmdline contains "NT AUT" or tgt.process.cmdline contains " SYSTEM ")) and (not ((src.process.image.path contains "\\AppData\\Local\\Temp\\" and src.process.image.path contains "TeamViewer_.exe") and tgt.process.image.path contains "\\schtasks.exe" and tgt.process.cmdline contains "/TN TVInstallRestore"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Schtasks Execution AppData Folder
id: c5c00f49-b3f9-45a6-997e-cfdecc6e1967
status: test
description: 'Detects the creation of a schtask that executes a file from C:\Users\<USER>\AppData\Local'
references:
    - https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-03-15
modified: 2022-07-28
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.005
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/Create'
            - '/RU'
            - '/TR'
            - 'C:\Users\'
            - '\AppData\Local\'
        CommandLine|contains:
            - 'NT AUT' # This covers the usual NT AUTHORITY\SYSTEM
            - ' SYSTEM ' # SYSTEM is a valid value for schtasks hence it gets it's own value with space
    filter:
        # FP from test set in SIGMA
        ParentImage|contains|all:
            - '\AppData\Local\Temp\'
            - 'TeamViewer_.exe'
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/TN TVInstallRestore'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
