```sql
// Translated content (automatically translated on 10-09-2026 03:38:18):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\endpointdlp.dll" and (not (module.path="c:\\programdata\\Microsoft\\Windows Defender\\Platform\\*\\*" or module.path="c:\\program files\\Windows Defender\\*\\*" or module.path="c:\\program files (x86)\\Windows Defender\\*\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of endpointdlp.dll
id: 9631881b-4228-48a3-4970-5b9ff8863388
status: experimental
description: Detects possible DLL hijacking of endpointdlp.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/endpointdlp.html
author: "Jose Oregon"
date: 2026-05-11
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\endpointdlp.dll'
    filter:
        ImageLoaded:
            - 'c:\programdata\Microsoft\Windows Defender\Platform\\*\\*'
            - 'c:\program files\Windows Defender\\*\\*'
            - 'c:\program files (x86)\Windows Defender\\*\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
