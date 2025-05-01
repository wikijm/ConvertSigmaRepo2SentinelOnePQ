```sql
// Translated content (automatically translated on 01-05-2025 01:50:47):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\appxdeploymentclient.dll" and (not (module.path in ("c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of appxdeploymentclient.dll
id: 7568421b-9395-48a3-4833-5b9ff8638490
status: experimental
description: Detects possible DLL hijacking of appxdeploymentclient.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/appxdeploymentclient.html
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
        ImageLoaded: '*\appxdeploymentclient.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
