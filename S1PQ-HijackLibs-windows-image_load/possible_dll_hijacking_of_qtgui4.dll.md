```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\qtgui4.dll" and (not (module.path in ("c:\program files\Audacity\*","c:\program files (x86)\Audacity\*","c:\program files\AOMEI\AOMEI Backupper\*\*","c:\program files (x86)\AOMEI\AOMEI Backupper\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of qtgui4.dll
id: 9746981b-4026-48a3-2477-5b9ff8238508
status: experimental
description: Detects possible DLL hijacking of qtgui4.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/qt/qtgui4.html
author: "Jai Minton - HuntressLabs"
date: 2025-04-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\qtgui4.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Audacity\*'
            - 'c:\program files (x86)\Audacity\*'
            - 'c:\program files\AOMEI\AOMEI Backupper\*\*'
            - 'c:\program files (x86)\AOMEI\AOMEI Backupper\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
