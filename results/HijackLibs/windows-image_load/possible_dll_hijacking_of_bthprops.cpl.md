```sql
// Translated content (automatically translated on 28-03-2026 02:28:12):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\bthprops.cpl" and (not (module.path contains "c:\\windows\\system32\\" or module.path contains "c:\\windows\\syswow64\\" or module.path contains "c:\\windows\\Prefetch\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of bthprops.cpl
id: 9160871b-3316-48a3-9077-5b9ff8347867
status: experimental
description: Detects possible DLL hijacking of bthprops.cpl by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/bthprops.html
author: "Swachchhanda Shrawan Poudel"
date: 2026-02-05
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\bthprops.cpl'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\\*'
            - 'c:\windows\syswow64\\*'
            - 'c:\windows\Prefetch\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
