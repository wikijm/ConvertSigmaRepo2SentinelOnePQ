```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\appvlp.exe" and (not (tgt.process.image.path contains ":\\Windows\\SysWOW64\\rundll32.exe" or tgt.process.image.path contains ":\\Windows\\System32\\rundll32.exe")) and (not ((tgt.process.image.path contains ":\\Program Files\\Microsoft Office" and tgt.process.image.path contains "\\msoasb.exe") or ((tgt.process.image.path contains ":\\Program Files\\Microsoft Office" and tgt.process.image.path contains "\\SkypeSrv\\") and tgt.process.image.path contains "\\SKYPESERVER.EXE") or (tgt.process.image.path contains ":\\Program Files\\Microsoft Office" and tgt.process.image.path contains "\\MSOUC.EXE")))))
```


# Original Sigma Rule:
```yaml
title: Uncommon Child Process Of Appvlp.EXE
id: 9c7e131a-0f2c-4ae0-9d43-b04f4e266d43
status: test
description: |
    Detects uncommon child processes of Appvlp.EXE
    Appvlp or the Application Virtualization Utility is included with Microsoft Office. Attackers are able to abuse "AppVLP" to execute shell commands.
    Normally, this binary is used for Application Virtualization, but it can also be abused to circumvent the ASR file path rule folder
    or to mark a file as a system file.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Appvlp/
author: Sreeman
date: 2020-03-13
modified: 2023-11-09
tags:
    - attack.t1218
    - attack.defense-evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\appvlp.exe'
    # Note: Filters based on data from EchoTrail: https://www.echotrail.io/insights/search/appvlp.exe/
    filter_main_generic:
        Image|endswith:
            - ':\Windows\SysWOW64\rundll32.exe'
            - ':\Windows\System32\rundll32.exe'
    filter_optional_office_msoasb:
        Image|contains: ':\Program Files\Microsoft Office'
        Image|endswith: '\msoasb.exe'
    filter_optional_office_skype:
        Image|contains|all:
            - ':\Program Files\Microsoft Office'
            - '\SkypeSrv\'
        Image|endswith: '\SKYPESERVER.EXE'
    filter_optional_office_msouc:
        Image|contains: ':\Program Files\Microsoft Office'
        Image|endswith: '\MSOUC.EXE'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
```
