```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\outllib.dll" and (not (module.path="c:\\program files\\Microsoft Office\\OFFICE*\*" or module.path="c:\\program files (x86)\\Microsoft Office\\OFFICE*\*" or module.path="c:\\program files\\Microsoft Office\\Root\\OFFICE*\*" or module.path="c:\\program files (x86)\\Microsoft Office\\Root\\OFFICE*\*" or module.path="c:\\program files\\Microsoft Office *\\ClientX86\\Root\\Office*\*" or module.path="c:\\program files (x86)\\Microsoft Office *\\ClientX86\\Root\\Office*\*" or module.path="c:\\program files\\Microsoft Office *\\ClientX64\\Root\\Office*\*" or module.path="c:\\program files (x86)\\Microsoft Office *\\ClientX64\\Root\\Office*\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of outllib.dll
id: 3802401b-1318-48a3-1317-5b9ff8856876
status: experimental
description: Detects possible DLL hijacking of outllib.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/outllib.html
author: "Wietze Beukema"
date: 2022-06-13
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\outllib.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Microsoft Office\OFFICE*\*'
            - 'c:\program files (x86)\Microsoft Office\OFFICE*\*'
            - 'c:\program files\Microsoft Office\Root\OFFICE*\*'
            - 'c:\program files (x86)\Microsoft Office\Root\OFFICE*\*'
            - 'c:\program files\Microsoft Office *\ClientX86\Root\Office*\*'
            - 'c:\program files (x86)\Microsoft Office *\ClientX86\Root\Office*\*'
            - 'c:\program files\Microsoft Office *\ClientX64\Root\Office*\*'
            - 'c:\program files (x86)\Microsoft Office *\ClientX64\Root\Office*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
