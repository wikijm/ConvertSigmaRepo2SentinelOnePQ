```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\webui.dll" and (not (module.path in ("c:\program files\iTop Screen Recorder\*","c:\program files (x86)\iTop Screen Recorder\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of webui.dll
id: 4693611b-3685-48a3-9733-5b9ff8797206
status: experimental
description: Detects possible DLL hijacking of webui.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/itop/webui.html
author: "Jai Minton - HuntressLabs"
date: 2024-08-30
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\webui.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\iTop Screen Recorder\*'
            - 'c:\program files (x86)\iTop Screen Recorder\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
