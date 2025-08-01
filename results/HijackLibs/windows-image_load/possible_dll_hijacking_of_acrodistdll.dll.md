```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\acrodistdll.dll" and (not (module.path="c:\program files\Adobe\Acrobat *\Acrobat\*" or module.path="c:\program files (x86)\Adobe\Acrobat *\Acrobat\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of acrodistdll.dll
id: 8335211b-4774-48a3-6608-5b9ff8433675
status: experimental
description: Detects possible DLL hijacking of acrodistdll.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/adobe/acrodistdll.html
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
        ImageLoaded: '*\acrodistdll.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Adobe\Acrobat *\Acrobat\*'
            - 'c:\program files (x86)\Adobe\Acrobat *\Acrobat\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
