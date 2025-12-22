```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\vmtools.dll" and (not (module.path in ("c:\\program files\\VMware\\VMware Tools\*","c:\\program files (x86)\\VMware\\VMware Tools\*","c:\\program files\\VMware\\VMware Workstation\*","c:\\program files (x86)\\VMware\\VMware Workstation\*","c:\\program files\\VMware\\VMware Player\*","c:\\program files (x86)\\VMware\\VMware Player\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vmtools.dll
id: 1454271b-2773-48a3-5383-5b9ff8169519
status: experimental
description: Detects possible DLL hijacking of vmtools.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/vmware/vmtools.html
author: "Jai Minton - HuntressLabs"
date: 2024-05-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vmtools.dll'
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
