```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\cnmpaui.dll" and (not (module.path contains "c:\\program files\\Canon\\Canon IJ Printer Assistant Tool\\" or module.path contains "c:\\program files (x86)\\Canon\\Canon IJ Printer Assistant Tool\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of cnmpaui.dll
id: 6937481b-1876-48a3-1767-5b9ff8172694
status: experimental
description: Detects possible DLL hijacking of cnmpaui.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/canon/cnmpaui.html
author: "Swachchhanda Shrawan Poudel"
date: 2025-09-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\cnmpaui.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Canon\Canon IJ Printer Assistant Tool\\*'
            - 'c:\program files (x86)\Canon\Canon IJ Printer Assistant Tool\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
