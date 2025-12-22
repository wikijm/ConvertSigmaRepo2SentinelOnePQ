```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\mpsvc.dll" and (not (module.path in ("c:\\programdata\\Microsoft\\Windows Defender\\Platform\*\*","c:\\program files\\Windows Defender\*\*","c:\\program files (x86)\\Windows Defender\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mpsvc.dll
id: 9492751b-1313-48a3-6160-5b9ff8899459
status: experimental
description: Detects possible DLL hijacking of mpsvc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/mpsvc.html
author: "Wietze Beukema"
date: 2021-12-07
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mpsvc.dll'
    filter:
        ImageLoaded:
            - 'c:\programdata\Microsoft\Windows Defender\Platform\*\*'
            - 'c:\program files\Windows Defender\*\*'
            - 'c:\program files (x86)\Windows Defender\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
