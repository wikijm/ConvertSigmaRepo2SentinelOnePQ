```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\wsc.dll" and (not (module.path in ("c:\\program files\\AVAST Software\\Avast\*","c:\\program files (x86)\\AVAST Software\\Avast\*","c:\\program files\\Norton\\Suite\*","c:\\program files (x86)\\Norton\\Suite\*","c:\\program files\\AVG\\Antivirus\*","c:\\program files (x86)\\AVG\\Antivirus\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wsc.dll
id: 2764371b-9122-48a3-7130-5b9ff8861115
status: experimental
description: Detects possible DLL hijacking of wsc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/avast/wsc.html
author: "Matt Green"
date: 2022-08-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wsc.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\AVAST Software\Avast\*'
            - 'c:\program files (x86)\AVAST Software\Avast\*'
            - 'c:\program files\Norton\Suite\*'
            - 'c:\program files (x86)\Norton\Suite\*'
            - 'c:\program files\AVG\Antivirus\*'
            - 'c:\program files (x86)\AVG\Antivirus\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
