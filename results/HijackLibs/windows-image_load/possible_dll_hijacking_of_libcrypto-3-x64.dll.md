```sql
// Translated content (automatically translated on 08-09-2026 03:35:44):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\libcrypto-3-x64.dll" and (not (module.path contains "c:\\program files\\VMware\\VMware Workstation\\x64\\" or module.path contains "c:\\program files (x86)\\VMware\\VMware Workstation\\x64\\" or module.path contains "c:\\program files\\VMware\\VMware Workstation\\" or module.path contains "c:\\program files (x86)\\VMware\\VMware Workstation\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libcrypto-3-x64.dll
id: 6753981b-4852-48a3-1520-5b9ff8234737
status: experimental
description: Detects possible DLL hijacking of libcrypto-3-x64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/vmware/libcrypto-3-x64.html
author: "Harry Godridge - HuntressLabs"
date: 2026-07-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libcrypto-3-x64.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\VMware\VMware Workstation\x64\\*'
            - 'c:\program files (x86)\VMware\VMware Workstation\x64\\*'
            - 'c:\program files\VMware\VMware Workstation\\*'
            - 'c:\program files (x86)\VMware\VMware Workstation\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
