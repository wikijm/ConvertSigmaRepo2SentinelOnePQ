```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\glib-2.0.dll" and (not (module.path in ("c:\program files\VMware\VMware Tools\*","c:\program files (x86)\VMware\VMware Tools\*","c:\program files\VMware\VMware Workstation\*","c:\program files (x86)\VMware\VMware Workstation\*","c:\program files\VMware\VMware Player\*","c:\program files (x86)\VMware\VMware Player\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of glib-2.0.dll
id: 7524131b-7740-48a3-2257-5b9ff8783090
status: experimental
description: Detects possible DLL hijacking of glib-2.0.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/vmware/glib-2.0.html
author: "Wietze Beukema"
date: 2023-04-03
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\glib-2.0.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\VMware\VMware Tools\*'
            - 'c:\program files (x86)\VMware\VMware Tools\*'
            - 'c:\program files\VMware\VMware Workstation\*'
            - 'c:\program files (x86)\VMware\VMware Workstation\*'
            - 'c:\program files\VMware\VMware Player\*'
            - 'c:\program files (x86)\VMware\VMware Player\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
