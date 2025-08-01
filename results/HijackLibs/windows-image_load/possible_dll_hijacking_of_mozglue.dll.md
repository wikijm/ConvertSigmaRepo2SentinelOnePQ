```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\mozglue.dll" and (not (module.path in ("c:\program files\SeaMonkey\*","c:\program files (x86)\SeaMonkey\*","c:\program files\Mozilla Firefox\*","c:\program files (x86)\Mozilla Firefox\*","c:\program files\Mozilla Thunderbird\*","c:\program files (x86)\Mozilla Thunderbird\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mozglue.dll
id: 6154931b-2326-48a3-2877-5b9ff8738308
status: experimental
description: Detects possible DLL hijacking of mozglue.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mozilla/mozglue.html
author: "Wietze Beukema"
date: 2022-09-26
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mozglue.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\SeaMonkey\*'
            - 'c:\program files (x86)\SeaMonkey\*'
            - 'c:\program files\Mozilla Firefox\*'
            - 'c:\program files (x86)\Mozilla Firefox\*'
            - 'c:\program files\Mozilla Thunderbird\*'
            - 'c:\program files (x86)\Mozilla Thunderbird\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
