```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\ppcore.dll" and (not (module.path="c:\\program files\\Microsoft Office\\OFFICE*\*" or module.path="c:\\program files (x86)\\Microsoft Office\\OFFICE*\*" or module.path="c:\\program files\\Microsoft Office\\Root\\OFFICE*\*" or module.path="c:\\program files (x86)\\Microsoft Office\\Root\\OFFICE*\*" or module.path="c:\\program files\\Microsoft Office *\\ClientX86\\Root\\Office*\*" or module.path="c:\\program files (x86)\\Microsoft Office *\\ClientX86\\Root\\Office*\*" or module.path="c:\\program files\\Microsoft Office *\\ClientX64\\Root\\Office*\*" or module.path="c:\\program files (x86)\\Microsoft Office *\\ClientX64\\Root\\Office*\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of ppcore.dll
id: 5961131b-2351-48a3-2815-5b9ff8263220
status: experimental
description: Detects possible DLL hijacking of ppcore.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/ppcore.html
author: "Swachchhanda Shrawan Poudel"
date: 2025-04-23
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\ppcore.dll'
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
