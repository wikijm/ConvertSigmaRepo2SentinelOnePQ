```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\chrome_frame_helper.dll" and (not (module.path contains "C:\\Program Files\\Google\\Chrome\\Application\\" or module.path contains "C:\\Program Files (x86)\\Google\\Chrome\\Application\\")) and (not module.path contains "\\AppData\\local\\Google\\Chrome\\Application\\")))
```


# Original Sigma Rule:
```yaml
title: Potential Chrome Frame Helper DLL Sideloading
id: 72ca7c75-bf85-45cd-aca7-255d360e423c
status: test
description: Detects potential DLL sideloading of "chrome_frame_helper.dll"
references:
    - https://hijacklibs.net/entries/3rd_party/google/chrome_frame_helper.html
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
date: 2022-08-17
modified: 2023-05-15
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
        ImageLoaded|endswith: '\chrome_frame_helper.dll'
    filter_main_path:
        ImageLoaded|startswith:
            - 'C:\Program Files\Google\Chrome\Application\'
            - 'C:\Program Files (x86)\Google\Chrome\Application\'
    filter_optional_user_path:
        ImageLoaded|contains: '\AppData\local\Google\Chrome\Application\'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
```
