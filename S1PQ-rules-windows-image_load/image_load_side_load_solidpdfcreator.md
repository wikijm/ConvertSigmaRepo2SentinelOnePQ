```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\SolidPDFCreator.dll" and (not (src.process.image.path contains "\SolidPDFCreator.exe" and (module.path contains "C:\Program Files (x86)\SolidDocuments\SolidPDFCreator\" or module.path contains "C:\Program Files\SolidDocuments\SolidPDFCreator\")))))
```


# Original Sigma Rule:
```yaml
title: Potential SolidPDFCreator.DLL Sideloading
id: a2edbce1-95c8-4291-8676-0d45146862b3
status: test
description: Detects potential DLL sideloading of "SolidPDFCreator.dll"
references:
    - https://lab52.io/blog/new-mustang-pandas-campaing-against-australia/
author: X__Junior (Nextron Systems)
date: 2023-05-07
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\SolidPDFCreator.dll'
    filter_main_path:
        Image|endswith: '\SolidPDFCreator.exe'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\SolidDocuments\SolidPDFCreator\'
            - 'C:\Program Files\SolidDocuments\SolidPDFCreator\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
