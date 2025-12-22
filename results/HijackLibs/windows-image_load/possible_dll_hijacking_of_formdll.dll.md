```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\formdll.dll" and (not (module.path in ("c:\\program files\\Common Files\\Microsoft Shared\\NoteSync Forms\*","c:\\program files (x86)\\Common Files\\Microsoft Shared\\NoteSync Forms\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of formdll.dll
id: 2943741b-3819-48a3-7381-5b9ff8215555
status: experimental
description: Detects possible DLL hijacking of formdll.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/formdll.html
author: "Wietze Beukema"
date: 2023-09-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\formdll.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Common Files\Microsoft Shared\NoteSync Forms\*'
            - 'c:\program files (x86)\Common Files\Microsoft Shared\NoteSync Forms\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
