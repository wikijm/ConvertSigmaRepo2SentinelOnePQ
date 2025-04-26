```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\atltracetoolui.dll" and (not (module.path in ("c:\program files\Microsoft Visual Studio 11.0\Common7\Tools\*","c:\program files (x86)\Microsoft Visual Studio 11.0\Common7\Tools\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of atltracetoolui.dll
id: 8132641b-4150-48a3-8413-5b9ff8149350
status: experimental
description: Detects possible DLL hijacking of atltracetoolui.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/atltracetoolui.html
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
        ImageLoaded: '*\atltracetoolui.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Microsoft Visual Studio 11.0\Common7\Tools\*'
            - 'c:\program files (x86)\Microsoft Visual Studio 11.0\Common7\Tools\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
