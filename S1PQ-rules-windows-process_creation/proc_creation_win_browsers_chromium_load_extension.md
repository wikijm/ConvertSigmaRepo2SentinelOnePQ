```sql
// Translated content (automatically translated on 14-10-2025 01:54:41):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\brave.exe" or tgt.process.image.path contains "\\chrome.exe" or tgt.process.image.path contains "\\msedge.exe" or tgt.process.image.path contains "\\opera.exe" or tgt.process.image.path contains "\\vivaldi.exe") and tgt.process.cmdline contains "--load-extension="))
```


# Original Sigma Rule:
```yaml
title: Chromium Browser Instance Executed With Custom Extension
id: 88d6e60c-759d-4ac1-a447-c0f1466c2d21
related:
    - id: 27ba3207-dd30-4812-abbf-5d20c57d474e
      type: similar
status: test
description: Detects a Chromium based browser process with the 'load-extension' flag to start a instance with a custom extension
references:
    - https://redcanary.com/blog/chromeloader/
    - https://emkc.org/s/RJjuLa
    - https://www.mandiant.com/resources/blog/lnk-between-browsers
author: Aedan Russell, frack113, X__Junior (Nextron Systems)
date: 2022-06-19
modified: 2023-11-28
tags:
    - attack.persistence
    - attack.t1176.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
        CommandLine|contains: '--load-extension='
    condition: selection
falsepositives:
    - Usage of Chrome Extensions in testing tools such as BurpSuite will trigger this alert
level: medium
```
