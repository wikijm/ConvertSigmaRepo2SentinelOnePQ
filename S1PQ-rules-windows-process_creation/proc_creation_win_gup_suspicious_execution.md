```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\GUP.exe" and (not ((tgt.process.image.path contains "\\Program Files\\Notepad++\\updater\\GUP.exe" or tgt.process.image.path contains "\\Program Files (x86)\\Notepad++\\updater\\GUP.exe") or (tgt.process.image.path contains "\\Users\\" and (tgt.process.image.path contains "\\AppData\\Local\\Notepad++\\updater\\GUP.exe" or tgt.process.image.path contains "\\AppData\\Roaming\\Notepad++\\updater\\GUP.exe"))))))
```


# Original Sigma Rule:
```yaml
title: Suspicious GUP Usage
id: 0a4f6091-223b-41f6-8743-f322ec84930b
status: test
description: Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks
references:
    - https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html
author: Florian Roth (Nextron Systems)
date: 2019-02-06
modified: 2022-08-13
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.defense-evasion
    - attack.t1574.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\GUP.exe'
    filter_programfiles:
        Image|endswith:
            - '\Program Files\Notepad++\updater\GUP.exe'
            - '\Program Files (x86)\Notepad++\updater\GUP.exe'
    filter_user:
        Image|contains: '\Users\'
        Image|endswith:
            - '\AppData\Local\Notepad++\updater\GUP.exe'
            - '\AppData\Roaming\Notepad++\updater\GUP.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Execution of tools named GUP.exe and located in folders different than Notepad++\updater
level: high
```
