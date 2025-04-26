```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\tts.dll" and (not (module.path in ("c:\program files\Soundpad\*","c:\program files (x86)\Soundpad\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tts.dll
id: 7423771b-1967-48a3-9518-5b9ff8557181
status: experimental
description: Detects possible DLL hijacking of tts.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/leppsoft/tts.html
author: "Walter Gordillo"
date: 2025-03-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tts.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Soundpad\*'
            - 'c:\program files (x86)\Soundpad\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
