```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((src.process.image.path contains "\\dism.exe" and module.path contains "\\dismcore.dll") and (not module.path="C:\\Windows\\System32\\Dism\\dismcore.dll")))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass With Fake DLL
id: a5ea83a7-05a5-44c1-be2e-addccbbd8c03
status: test
description: Attempts to load dismcore.dll after dropping it
references:
    - https://steemit.com/utopian-io/@ah101/uac-bypassing-utility
author: oscd.community, Dmitry Uchakin
date: 2020-10-06
modified: 2022-12-25
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\dism.exe'
        ImageLoaded|endswith: '\dismcore.dll'
    filter:
        ImageLoaded: 'C:\Windows\System32\Dism\dismcore.dll'
    condition: selection and not filter
falsepositives:
    - Actions of a legitimate telnet client
level: high
```
