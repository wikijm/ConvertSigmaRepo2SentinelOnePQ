```sql
// Translated content (automatically translated on 24-07-2025 01:56:06):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\offdmpsvc.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of offdmpsvc.dll
id: 1236341b-2879-48a3-1562-5b9ff8542681
status: experimental
description: Detects possible DLL hijacking of offdmpsvc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/offdmpsvc.html
author: "Swachchhanda Shrawan Poudel"
date: 2025-06-17
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\offdmpsvc.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
