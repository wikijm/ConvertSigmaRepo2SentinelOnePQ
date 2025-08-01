```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\mpclient.dll" and (not (module.path in ("c:\program files\Windows Defender\*","c:\program files (x86)\Windows Defender\*","c:\programdata\Microsoft\Windows Defender\Platform\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mpclient.dll
id: 9533391b-5388-48a3-9769-5b9ff8396239
status: experimental
description: Detects possible DLL hijacking of mpclient.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/mpclient.html
author: "Wietze Beukema"
date: 2022-08-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mpclient.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Windows Defender\*'
            - 'c:\program files (x86)\Windows Defender\*'
            - 'c:\programdata\Microsoft\Windows Defender\Platform\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
