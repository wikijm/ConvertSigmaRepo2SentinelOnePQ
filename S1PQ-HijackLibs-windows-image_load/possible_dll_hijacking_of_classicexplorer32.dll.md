```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\classicexplorer32.dll" and (not (module.path in ("c:\program files\Classic Shell\*","c:\program files (x86)\Classic Shell\*","c:\program files\Open-Shell\*","c:\program files (x86)\Open-Shell\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of classicexplorer32.dll
id: 1270151b-4774-48a3-6608-5b9ff8770283
status: experimental
description: Detects possible DLL hijacking of classicexplorer32.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/classicshell/classicexplorer32.html
author: "Pokhlebin Maxim"
date: 2023-06-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\classicexplorer32.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Classic Shell\*'
            - 'c:\program files (x86)\Classic Shell\*'
            - 'c:\program files\Open-Shell\*'
            - 'c:\program files (x86)\Open-Shell\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
