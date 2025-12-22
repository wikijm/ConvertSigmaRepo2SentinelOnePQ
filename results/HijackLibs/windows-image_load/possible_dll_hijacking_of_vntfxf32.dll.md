```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\vntfxf32.dll" and (not (module.path in ("c:\\program files\\Venta\\VentaFax & Voice\*","c:\\program files (x86)\\Venta\\VentaFax & Voice\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vntfxf32.dll
id: 5845121b-4150-48a3-8413-5b9ff8327495
status: experimental
description: Detects possible DLL hijacking of vntfxf32.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/ventafax/vntfxf32.html
author: "Wietze Beukema"
date: 2023-04-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vntfxf32.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Venta\VentaFax & Voice\*'
            - 'c:\program files (x86)\Venta\VentaFax & Voice\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
