```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\WINWORD.EXE" or src.process.image.path contains "\\EXCEL.EXE" or src.process.image.path contains "\\POWERPNT.exe" or src.process.image.path contains "\\MSPUB.exe" or src.process.image.path contains "\\VISIO.exe" or src.process.image.path contains "\\MSACCESS.exe" or src.process.image.path contains "\\EQNEDT32.exe") and tgt.process.image.path contains "C:\\users\\" and tgt.process.image.path contains ".exe") and (not tgt.process.image.path contains "\\Teams.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Binary In User Directory Spawned From Office Application
id: aa3a6f94-890e-4e22-b634-ffdfd54792cc
status: test
description: Detects an executable in the users directory started from one of the Microsoft Office suite applications (Word, Excel, PowerPoint, Publisher, Visio)
references:
    - https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign
    - https://www.virustotal.com/gui/file/23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57
author: Jason Lynch
date: 2019-04-02
modified: 2023-02-04
tags:
    - attack.execution
    - attack.t1204.002
    - attack.g0046
    - car.2013-05-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.exe'
            - '\MSPUB.exe'
            - '\VISIO.exe'
            - '\MSACCESS.exe'
            - '\EQNEDT32.exe'
            # - '\OUTLOOK.EXE' too many FPs
        Image|startswith: 'C:\users\'
        Image|endswith: '.exe'
    filter:
        Image|endswith: '\Teams.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
