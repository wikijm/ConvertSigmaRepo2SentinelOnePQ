```sql
// Translated content (automatically translated on 17-05-2025 01:42:20):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\proximityservicepal.dll" and (not module.path="c:\windows\system32\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of proximityservicepal.dll
id: 9554351b-7437-48a3-2115-5b9ff8177990
status: experimental
description: Detects possible DLL hijacking of proximityservicepal.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/proximityservicepal.html
author: "Chris Spehn"
date: 2021-08-17
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\proximityservicepal.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
