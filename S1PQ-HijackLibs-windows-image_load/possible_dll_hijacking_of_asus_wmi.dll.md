```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\asus_wmi.dll" and (not (module.path in ("c:\program files\ASUS\AXSP\*\*","c:\program files (x86)\ASUS\AXSP\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of asus_wmi.dll
id: 9261901b-9521-48a3-3514-5b9ff8164788
status: experimental
description: Detects possible DLL hijacking of asus_wmi.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/asus/asus_wmi.html
author: "Jai Minton - HuntressLabs"
date: 2024-04-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\asus_wmi.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\ASUS\AXSP\*\*'
            - 'c:\program files (x86)\ASUS\AXSP\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
