```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\cmd.exe" or src.process.image.path contains "\\cscript.exe" or src.process.image.path contains "\\mshta.exe" or src.process.image.path contains "\\powershell.exe" or src.process.image.path contains "\\pwsh.exe" or src.process.image.path contains "\\regsvr32.exe" or src.process.image.path contains "\\rundll32.exe" or src.process.image.path contains "\\wscript.exe") and (tgt.process.image.path contains "\\brave.exe" or tgt.process.image.path contains "\\chrome.exe" or tgt.process.image.path contains "\\msedge.exe" or tgt.process.image.path contains "\\opera.exe" or tgt.process.image.path contains "\\vivaldi.exe") and tgt.process.cmdline contains "--load-extension="))
```


# Original Sigma Rule:
```yaml
title: Suspicious Chromium Browser Instance Executed With Custom Extension
id: 27ba3207-dd30-4812-abbf-5d20c57d474e
related:
    - id: 88d6e60c-759d-4ac1-a447-c0f1466c2d21
      type: similar
status: test
description: Detects a suspicious process spawning a Chromium based browser process with the 'load-extension' flag to start an instance with a custom extension
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
        ParentImage|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\wscript.exe'
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
        CommandLine|contains: '--load-extension='
    condition: selection
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_browsers_chromium_susp_load_extension/info.yml
```
