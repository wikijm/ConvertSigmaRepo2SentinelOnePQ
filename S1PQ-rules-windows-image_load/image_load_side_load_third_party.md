```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((module.path contains "\\commfunc.dll" and (not (module.path contains "\\AppData\\local\\Google\\Chrome\\Application\\" or (module.path contains "C:\\Program Files\\Lenovo\\Communications Utility\\" or module.path contains "C:\\Program Files (x86)\\Lenovo\\Communications Utility\\")))) or (module.path contains "\\tosbtkbd.dll" and (not (module.path contains "C:\\Program Files\\Toshiba\\Bluetooth Toshiba Stack\\" or module.path contains "C:\\Program Files (x86)\\Toshiba\\Bluetooth Toshiba Stack\\")))))
```


# Original Sigma Rule:
```yaml
title: Third Party Software DLL Sideloading
id: f9df325d-d7bc-4a32-8a1a-2cc61dcefc63
status: test
description: Detects DLL sideloading of DLLs that are part of third party software (zoom, discord....etc)
references:
    - https://hijacklibs.net/ # For list of DLLs that could be sideloaded (search for dlls mentioned here in there)
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
date: 2022-08-17
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    # Lenovo
    selection_lenovo:
        ImageLoaded|endswith: '\commfunc.dll'
    filter_lenovo:
        - ImageLoaded|contains: '\AppData\local\Google\Chrome\Application\'
        - ImageLoaded|startswith:
              - 'C:\Program Files\Lenovo\Communications Utility\'
              - 'C:\Program Files (x86)\Lenovo\Communications Utility\'
    # Toshiba
    selection_toshiba:
        ImageLoaded|endswith: '\tosbtkbd.dll'
    filter_toshiba:
        ImageLoaded|startswith:
            - 'C:\Program Files\Toshiba\Bluetooth Toshiba Stack\'
            - 'C:\Program Files (x86)\Toshiba\Bluetooth Toshiba Stack\'
    # Zoom (FP with System32)
    # selection_zoom:
    #     ImageLoaded|endswith: '\version.dll'
    # filter_zoom:
    #     ImageLoaded|startswith: 'C:\Users\'
    #     ImageLoaded|contains: '\AppData\Roaming\Zoom\bin\'
    condition: (selection_lenovo and not filter_lenovo) or (selection_toshiba and not filter_toshiba)
falsepositives:
    - Unknown
level: medium
```
