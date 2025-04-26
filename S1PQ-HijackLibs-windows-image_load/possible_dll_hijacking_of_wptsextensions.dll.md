```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\wptsextensions.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wptsextensions.dll
id: 5524021b-9122-48a3-7130-5b9ff8916642
status: experimental
description: Detects possible DLL hijacking of wptsextensions.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/wptsextensions.html
author: "k4nfr3"
date: 2022-08-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wptsextensions.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
