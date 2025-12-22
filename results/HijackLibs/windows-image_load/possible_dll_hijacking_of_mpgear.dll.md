```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\mpgear.dll" and (not (module.path in ("c:\\program files\\Windows Defender Advanced Threat Protection\\Classification\*","c:\\program files (x86)\\Windows Defender Advanced Threat Protection\\Classification\*","c:\\windows\\system32\\MRT\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mpgear.dll
id: 1970121b-9569-48a3-1936-5b9ff8709922
status: experimental
description: Detects possible DLL hijacking of mpgear.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/mpgear.html
author: "Jai Minton - HuntressLabs"
date: 2024-04-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mpgear.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Windows Defender Advanced Threat Protection\Classification\*'
            - 'c:\program files (x86)\Windows Defender Advanced Threat Protection\Classification\*'
            - 'c:\windows\system32\MRT\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
