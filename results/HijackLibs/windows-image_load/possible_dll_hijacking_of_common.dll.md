```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\common.dll" and (not (module.path in ("c:\\program files\\iroot\*","c:\\program files (x86)\\iroot\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of common.dll
id: 1355321b-4266-48a3-3778-5b9ff8480154
status: experimental
description: Detects possible DLL hijacking of common.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/iroot/common.html
author: "Jai Minton"
date: 2025-05-05
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\common.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\iroot\*'
            - 'c:\program files (x86)\iroot\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
