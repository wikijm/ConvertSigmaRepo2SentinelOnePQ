```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\windowsperformancerecordercontrol.dll" and (not (module.path in ("c:\program files\windows kits\10\windows performance toolkit\*","c:\program files (x86)\windows kits\10\windows performance toolkit\*","c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of windowsperformancerecordercontrol.dll
id: 1224551b-9395-48a3-4833-5b9ff8366003
status: experimental
description: Detects possible DLL hijacking of windowsperformancerecordercontrol.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/windowsperformancerecordercontrol.html
author: "Wietze Beukema"
date: 2021-02-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\windowsperformancerecordercontrol.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\windows kits\10\windows performance toolkit\*'
            - 'c:\program files (x86)\windows kits\10\windows performance toolkit\*'
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
