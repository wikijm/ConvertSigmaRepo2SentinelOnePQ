```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\tosbtkbd.dll" and (not (module.path in ("c:\\program files\\Toshiba\\Bluetooth Toshiba Stack\*","c:\\program files (x86)\\Toshiba\\Bluetooth Toshiba Stack\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tosbtkbd.dll
id: 9671701b-6727-48a3-6557-5b9ff8159819
status: experimental
description: Detects possible DLL hijacking of tosbtkbd.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/toshiba/tosbtkbd.html
author: "Wietze Beukema"
date: 2022-06-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tosbtkbd.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Toshiba\Bluetooth Toshiba Stack\*'
            - 'c:\program files (x86)\Toshiba\Bluetooth Toshiba Stack\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
