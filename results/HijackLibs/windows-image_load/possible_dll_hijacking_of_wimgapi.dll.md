```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\wimgapi.dll" and (not (module.path in ("c:\windows\system32\*","c:\windows\syswow64\*","c:\program files\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\arm64\DISM\*","c:\program files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\arm64\DISM\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wimgapi.dll
id: 1854941b-9395-48a3-4833-5b9ff8418066
status: experimental
description: Detects possible DLL hijacking of wimgapi.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/wimgapi.html
author: "Wietze Beukema"
date: 2021-02-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wimgapi.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'
            - 'c:\program files\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\arm64\DISM\*'
            - 'c:\program files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\arm64\DISM\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
