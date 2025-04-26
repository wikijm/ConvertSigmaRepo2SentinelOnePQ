```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\fxsapi.dll" and (not (module.path="c:\windows\system32\*" or module.path="c:\windows\system32\driverstore\filerepository\prnms002.inf_*\amd64\*" or module.path="c:\windows\syswow64\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of fxsapi.dll
id: 6908811b-9395-48a3-4833-5b9ff8134207
status: experimental
description: Detects possible DLL hijacking of fxsapi.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/fxsapi.html
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
        ImageLoaded: '*\fxsapi.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\system32\driverstore\filerepository\prnms002.inf_*\amd64\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
