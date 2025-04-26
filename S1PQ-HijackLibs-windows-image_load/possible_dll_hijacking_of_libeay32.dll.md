```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\libeay32.dll" and (not (module.path in ("c:\program files\PSPad editor\*","c:\program files (x86)\PSPad editor\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libeay32.dll
id: 9896461b-9569-48a3-1936-5b9ff8233096
status: experimental
description: Detects possible DLL hijacking of libeay32.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/pspad/libeay32.html
author: "Jai Minton - HuntressLabs"
date: 2024-04-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libeay32.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\PSPad editor\*'
            - 'c:\program files (x86)\PSPad editor\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
