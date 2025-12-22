```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\axeonoffhelper.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of axeonoffhelper.dll
id: 7616971b-8288-48a3-2577-5b9ff8451750
status: experimental
description: Detects possible DLL hijacking of axeonoffhelper.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/axeonoffhelper.html
author: "Swachchhanda Shrawan Poudel"
date: 2025-06-18
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\axeonoffhelper.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
