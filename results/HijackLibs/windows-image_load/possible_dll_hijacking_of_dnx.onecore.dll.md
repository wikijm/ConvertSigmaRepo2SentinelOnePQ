```sql
// Translated content (automatically translated on 08-09-2026 03:35:44):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\dnx.onecore.dll" and (not (module.path contains "c:\\program files\\Microsoft Web Tools\\DNX\\" or module.path contains "c:\\program files (x86)\\Microsoft Web Tools\\DNX\\" or module.path="C:\\Users\\*\\.dnx\\runtimes\\*\\bin\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dnx.onecore.dll
id: 4220921b-5855-48a3-4834-5b9ff8951405
status: experimental
description: Detects possible DLL hijacking of dnx.onecore.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/dnx.onecore.html
author: "Swachchhanda Shrawan Poudel"
date: 2026-04-23
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\dnx.onecore.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Microsoft Web Tools\DNX\\*'
            - 'c:\program files (x86)\Microsoft Web Tools\DNX\\*'
            - 'C:\Users\\*\.dnx\runtimes\\*\bin\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
