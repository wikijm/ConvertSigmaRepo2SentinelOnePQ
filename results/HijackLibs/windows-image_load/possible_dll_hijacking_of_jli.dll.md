```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\jli.dll" and (not (module.path in ("c:\\program files\\Java\*\\bin\*","c:\\program files (x86)\\Java\*\\bin\*","c:\\program files\*\\jre\\bin\*","c:\\program files (x86)\*\\jre\\bin\*","c:\\users\*\\appdata\\local\\Temp\*\\bin\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of jli.dll
id: 3307531b-4890-48a3-2757-5b9ff8183967
status: experimental
description: Detects possible DLL hijacking of jli.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/oracle/jli.html
author: "Swachchhanda Shrawan Poudel"
date: 2025-07-09
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\jli.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Java\*\bin\*'
            - 'c:\program files (x86)\Java\*\bin\*'
            - 'c:\program files\*\jre\bin\*'
            - 'c:\program files (x86)\*\jre\bin\*'
            - 'c:\users\*\appdata\local\Temp\*\bin\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
