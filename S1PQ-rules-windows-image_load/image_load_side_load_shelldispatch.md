```sql
// Translated content (automatically translated on 03-09-2025 01:10:58):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\ShellDispatch.dll" and (not ((module.path contains ":\\Users\\" and module.path contains "\\AppData\\Local\\Temp\\") or module.path contains ":\\Windows\\Temp\\"))))
```


# Original Sigma Rule:
```yaml
title: Potential ShellDispatch.DLL Sideloading
id: 844f8eb2-610b-42c8-89a4-47596e089663
status: test
description: Detects potential DLL sideloading of "ShellDispatch.dll"
references:
    - https://www.hexacorn.com/blog/2023/06/07/this-lolbin-doesnt-exist/
author: X__Junior (Nextron Systems)
date: 2023-06-20
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\ShellDispatch.dll'
    filter_main_legit_path:
        - ImageLoaded|contains|all:
              - ':\Users\'
              - '\AppData\Local\Temp\'
        - ImageLoaded|contains: ':\Windows\Temp\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Some installers may trigger some false positives
level: medium
```
