```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\avdevice-54.dll" and (not (module.path in ("c:\program files\AnyMP4 Studio\AnyMP4 Blu-ray Creator\*","c:\program files (x86)\AnyMP4 Studio\AnyMP4 Blu-ray Creator\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of avdevice-54.dll
id: 1624171b-6171-48a3-7472-5b9ff8676420
status: experimental
description: Detects possible DLL hijacking of avdevice-54.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/anymp4/avdevice-54.html
author: "Jai Minton - HuntressLabs"
date: 2024-05-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\avdevice-54.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\AnyMP4 Studio\AnyMP4 Blu-ray Creator\*'
            - 'c:\program files (x86)\AnyMP4 Studio\AnyMP4 Blu-ray Creator\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
