```sql
// Translated content (automatically translated on 22-12-2025 00:55:34):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains ":\\Temp\\" or src.process.image.path contains "\\AppData\\Local\\" or src.process.image.path contains "\\AppData\\Roaming\\" or src.process.image.path contains "\\Temporary Internet" or src.process.image.path contains "\\Users\\Public\\" or src.process.image.path contains "\\Windows\\Temp\\") and tgt.process.image.path contains "\\schtasks.exe" and tgt.process.cmdline contains "/Create ") and (not (tgt.process.cmdline contains "update_task.xml" or tgt.process.cmdline contains "unattended.ini"))))
```


# Original Sigma Rule:
```yaml
title: Scheduled Task Creation From Potential Suspicious Parent Location
id: 9494479d-d994-40bf-a8b1-eea890237021
status: test
description: |
    Detects the execution of "schtasks.exe" from a parent that is located in a potentially suspicious location.
    Multiple malware strains were seen exhibiting a similar behavior in order to achieve persistence.
references:
    - https://app.any.run/tasks/649e7b46-9bec-4d05-98a5-dfa9a13eaae5/
author: Florian Roth (Nextron Systems)
date: 2022-02-23
modified: 2024-05-13
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1053.005
    - detection.threat-hunting
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|contains:
            - ':\Temp\'
            - '\AppData\Local\'
            - '\AppData\Roaming\'
            - '\Temporary Internet'
            - '\Users\Public\'
            - '\Windows\Temp\'
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/Create '
    filter_optional_common:
        CommandLine|contains:
            - 'update_task.xml'
            - 'unattended.ini'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Software installers that run from temporary folders and also install scheduled tasks
level: medium
```
