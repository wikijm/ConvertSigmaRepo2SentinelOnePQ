```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\amindpdfcore.dll" and (not (module.path in ("c:\program files\GeekerPDF\GeekerPDF\*","c:\program files (x86)\GeekerPDF\GeekerPDF\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of amindpdfcore.dll
id: 5350481b-6363-48a3-2268-5b9ff8814206
status: experimental
description: Detects possible DLL hijacking of amindpdfcore.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/amindpdf/amindpdfcore.html
author: "Still Hsu"
date: 2024-05-26
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\amindpdfcore.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\GeekerPDF\GeekerPDF\*'
            - 'c:\program files (x86)\GeekerPDF\GeekerPDF\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
