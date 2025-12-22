```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\schtasks.exe" and (tgt.process.cmdline contains " /create " and tgt.process.cmdline contains " /sc once " and tgt.process.cmdline contains "\\Temp\\")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Scheduled Task Creation Involving Temp Folder
id: 39019a4e-317f-4ce3-ae63-309a8c6b53c5
status: test
description: Detects the creation of scheduled tasks that involves a temporary folder and runs only once
references:
    - https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3
author: Florian Roth (Nextron Systems)
date: 2021-03-11
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - ' /create '
            - ' /sc once '
            - '\Temp\'
    condition: selection
falsepositives:
    - Administrative activity
    - Software installation
level: high
```
