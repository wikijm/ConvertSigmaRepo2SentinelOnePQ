```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\mfcu100u.dll" and (not (module.path in ("c:\\program files\\TechSmith\\Camtasia Studio 8\*","c:\\program files (x86)\\TechSmith\\Camtasia Studio 8\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mfcu100u.dll
id: 2066801b-7232-48a3-9635-5b9ff8811420
status: experimental
description: Detects possible DLL hijacking of mfcu100u.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/techsmith/mfcu100u.html
author: "Josh Allman"
date: 2025-02-28
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mfcu100u.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\TechSmith\Camtasia Studio 8\*'
            - 'c:\program files (x86)\TechSmith\Camtasia Studio 8\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
