```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\tedutil.dll" and (not (module.path in ("c:\program files\Microsoft SDKs\Windows\*\Bin\*","c:\program files (x86)\Microsoft SDKs\Windows\*\Bin\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tedutil.dll
id: 1524821b-9569-48a3-1936-5b9ff8301879
status: experimental
description: Detects possible DLL hijacking of tedutil.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/tedutil.html
author: "Jai Minton - HuntressLabs"
date: 2024-04-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tedutil.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Microsoft SDKs\Windows\*\Bin\*'
            - 'c:\program files (x86)\Microsoft SDKs\Windows\*\Bin\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
