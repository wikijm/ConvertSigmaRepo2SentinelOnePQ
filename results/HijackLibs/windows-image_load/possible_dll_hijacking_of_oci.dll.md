```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\oci.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of oci.dll
id: 4360571b-4908-48a3-8140-5b9ff8970133
status: experimental
description: Detects possible DLL hijacking of oci.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/oci.html
author: "Wietze Beukema"
date: 2022-06-12
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\oci.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
