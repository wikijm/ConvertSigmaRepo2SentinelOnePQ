```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\wwlib.dll" and (not ((src.process.image.path contains "C:\Program Files (x86)\Microsoft Office\" or src.process.image.path contains "C:\Program Files\Microsoft Office\") and src.process.image.path contains "\winword.exe" and (module.path contains "C:\Program Files (x86)\Microsoft Office\" or module.path contains "C:\Program Files\Microsoft Office\")))))
```


# Original Sigma Rule:
```yaml
title: Potential WWlib.DLL Sideloading
id: e2e01011-5910-4267-9c3b-4149ed5479cf
status: test
description: Detects potential DLL sideloading of "wwlib.dll"
references:
    - https://twitter.com/WhichbufferArda/status/1658829954182774784
    - https://news.sophos.com/en-us/2022/11/03/family-tree-dll-sideloading-cases-may-be-related/
    - https://securelist.com/apt-luminousmoth/103332/
author: X__Junior (Nextron Systems)
date: 2023-05-18
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\wwlib.dll'
    filter_main_path:
        Image|startswith:
            - 'C:\Program Files (x86)\Microsoft Office\'
            - 'C:\Program Files\Microsoft Office\'
        Image|endswith: '\winword.exe'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\Microsoft Office\'
            - 'C:\Program Files\Microsoft Office\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
