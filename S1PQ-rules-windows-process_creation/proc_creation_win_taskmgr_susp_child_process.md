```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\taskmgr.exe" and (not (tgt.process.image.path contains ":\\Windows\\System32\\mmc.exe" or tgt.process.image.path contains ":\\Windows\\System32\\resmon.exe" or tgt.process.image.path contains ":\\Windows\\System32\\Taskmgr.exe"))))
```


# Original Sigma Rule:
```yaml
title: New Process Created Via Taskmgr.EXE
id: 3d7679bd-0c00-440c-97b0-3f204273e6c7
status: test
description: Detects the creation of a process via the Windows task manager. This might be an attempt to bypass UAC
references:
    - https://twitter.com/ReneFreingruber/status/1172244989335810049
author: Florian Roth (Nextron Systems)
date: 2018-03-13
modified: 2024-01-18
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\taskmgr.exe'
    filter_main_generic:
        Image|endswith:
            - ':\Windows\System32\mmc.exe'
            - ':\Windows\System32\resmon.exe'
            - ':\Windows\System32\Taskmgr.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Administrative activity
level: low
```
