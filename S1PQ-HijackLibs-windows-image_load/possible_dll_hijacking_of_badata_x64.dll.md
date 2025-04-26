```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\badata_x64.dll" and (not (module.path in ("c:\program files\True Burner\*","c:\program files (x86)\True Burner\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of badata_x64.dll
id: 9713721b-9521-48a3-3514-5b9ff8143088
status: experimental
description: Detects possible DLL hijacking of badata_x64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/glorylogic/badata_x64.html
author: "Jai Minton - HuntressLabs"
date: 2024-04-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\badata_x64.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\True Burner\*'
            - 'c:\program files (x86)\True Burner\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
