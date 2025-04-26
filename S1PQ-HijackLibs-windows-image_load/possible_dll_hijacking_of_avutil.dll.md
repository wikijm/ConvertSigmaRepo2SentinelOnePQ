```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\avutil.dll" and (not (module.path in ("c:\program files\VSO\ConvertX\7\*","c:\program files (x86)\VSO\ConvertX\7\*","c:\program files\VSO\convertXtoDVD\*","c:\program files (x86)\VSO\convertXtoDVD\*","c:\program files\Common Files\Oracle\Java\javapath\*","c:\program files (x86)\Common Files\Oracle\Java\javapath\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of avutil.dll
id: 4821731b-3109-48a3-1955-5b9ff8677522
status: experimental
description: Detects possible DLL hijacking of avutil.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/vsosoftware/avutil.html
author: "Wietze Beukema"
date: 2024-07-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\avutil.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\VSO\ConvertX\7\*'
            - 'c:\program files (x86)\VSO\ConvertX\7\*'
            - 'c:\program files\VSO\convertXtoDVD\*'
            - 'c:\program files (x86)\VSO\convertXtoDVD\*'
            - 'c:\program files\Common Files\Oracle\Java\javapath\*'
            - 'c:\program files (x86)\Common Files\Oracle\Java\javapath\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
