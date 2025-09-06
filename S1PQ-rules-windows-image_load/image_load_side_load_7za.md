```sql
// Translated content (automatically translated on 06-09-2025 01:10:23):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\7za.dll" and (not ((src.process.image.path contains "C:\\Program Files (x86)\\" or src.process.image.path contains "C:\\Program Files\\") and (module.path contains "C:\\Program Files (x86)\\" or module.path contains "C:\\Program Files\\")))))
```


# Original Sigma Rule:
```yaml
title: Potential 7za.DLL Sideloading
id: 4f6edb78-5c21-42ab-a558-fd2a6fc1fd57
status: test
description: Detects potential DLL sideloading of "7za.dll"
references:
    - https://www.gov.pl/attachment/ee91f24d-3e67-436d-aa50-7fa56acf789d
author: X__Junior
date: 2023-06-09
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\7za.dll'
    filter_main_legit_path:
        Image|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate third party application located in "AppData" may leverage this DLL to offer 7z compression functionality and may generate false positives. Apply additional filters as needed.
level: low
```
