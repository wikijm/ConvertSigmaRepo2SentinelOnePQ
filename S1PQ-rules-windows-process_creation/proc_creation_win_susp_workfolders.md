```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\control.exe" and src.process.image.path contains "\WorkFolders.exe") and (not tgt.process.image.path="C:\Windows\System32\control.exe")))
```


# Original Sigma Rule:
```yaml
title: Execution via WorkFolders.exe
id: 0bbc6369-43e3-453d-9944-cae58821c173
status: test
description: Detects using WorkFolders.exe to execute an arbitrary control.exe
references:
    - https://twitter.com/elliotkillick/status/1449812843772227588
author: Maxime Thiebaut (@0xThiebaut)
date: 2021-10-21
modified: 2022-12-25
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\control.exe'
        ParentImage|endswith: '\WorkFolders.exe'
    filter:
        Image: 'C:\Windows\System32\control.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate usage of the uncommon Windows Work Folders feature.
level: high
```
