```sql
// Translated content (automatically translated on 06-09-2026 03:30:39):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\hostfxr.dll" and (not (module.path="c:\\program files\\dotnet\\host\\fxr\\*\\*" or module.path="c:\\program files (x86)\\dotnet\\host\\fxr\\*\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of hostfxr.dll
id: 1267681b-6191-48a3-2740-5b9ff8121560
status: experimental
description: Detects possible DLL hijacking of hostfxr.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/hostfxr.html
author: "Jose Oregon"
date: 2026-05-28
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\hostfxr.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\dotnet\host\fxr\\*\\*'
            - 'c:\program files (x86)\dotnet\host\fxr\\*\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
