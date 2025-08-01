```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\qt5core.dll" and (not (module.path in ("c:\program files\Electronic Arts\EA Desktop\EA Desktop\*","c:\program files (x86)\Electronic Arts\EA Desktop\EA Desktop\*","c:\program files\Microsoft Onedrive\*\*","c:\program files (x86)\Microsoft Onedrive\*\*","c:\users\*\appdata\local\Microsoft\Onedrive\*\*","c:\program files\Dropbox\Client\*\*","c:\program files (x86)\Dropbox\Client\*\*","c:\program files\LogiOptionsPlus\*","c:\program files (x86)\LogiOptionsPlus\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of qt5core.dll
id: 2527591b-4736-48a3-5188-5b9ff8167954
status: experimental
description: Detects possible DLL hijacking of qt5core.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/qt/qt5core.html
author: "Jai Minton - HuntressLabs"
date: 2024-06-13
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\qt5core.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Electronic Arts\EA Desktop\EA Desktop\*'
            - 'c:\program files (x86)\Electronic Arts\EA Desktop\EA Desktop\*'
            - 'c:\program files\Microsoft Onedrive\*\*'
            - 'c:\program files (x86)\Microsoft Onedrive\*\*'
            - 'c:\users\*\appdata\local\Microsoft\Onedrive\*\*'
            - 'c:\program files\Dropbox\Client\*\*'
            - 'c:\program files (x86)\Dropbox\Client\*\*'
            - 'c:\program files\LogiOptionsPlus\*'
            - 'c:\program files (x86)\LogiOptionsPlus\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
