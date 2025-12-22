```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\miracastview.dll" and (not module.path="c:\\windows\\Miracast\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of miracastview.dll
id: 6584331b-8048-48a3-5501-5b9ff8874671
status: experimental
description: Detects possible DLL hijacking of miracastview.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/miracastview.html
author: "Wietze Beukema"
date: 2025-05-24
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\miracastview.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\Miracast\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
