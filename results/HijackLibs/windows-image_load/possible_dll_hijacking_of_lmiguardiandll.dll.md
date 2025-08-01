```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\lmiguardiandll.dll" and (not (module.path in ("c:\program files\LogMeIn\*","c:\program files (x86)\LogMeIn\*","c:\program files\LogMeIn\x86\*","c:\program files (x86)\LogMeIn\x86\*","c:\program files\LogMeIn\x64\*","c:\program files (x86)\LogMeIn\x64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of lmiguardiandll.dll
id: 8056821b-5153-48a3-7359-5b9ff8983958
status: experimental
description: Detects possible DLL hijacking of lmiguardiandll.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/logmein/lmiguardiandll.html
author: "Christiaan Beek"
date: 2023-01-11
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\lmiguardiandll.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\LogMeIn\*'
            - 'c:\program files (x86)\LogMeIn\*'
            - 'c:\program files\LogMeIn\x86\*'
            - 'c:\program files (x86)\LogMeIn\x86\*'
            - 'c:\program files\LogMeIn\x64\*'
            - 'c:\program files (x86)\LogMeIn\x64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
