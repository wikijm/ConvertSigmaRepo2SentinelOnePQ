```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\rastls.dll" and (not (module.path in ("c:\program files\Symantec\Network Connected Devices Auto Setup\*","c:\program files (x86)\Symantec\Network Connected Devices Auto Setup\*","c:\windows\system32\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of rastls.dll
id: 2346691b-1995-48a3-3467-5b9ff8265175
status: experimental
description: Detects possible DLL hijacking of rastls.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/symantec/rastls.html
author: "Wietze Beukema"
date: 2023-02-26
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\rastls.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Symantec\Network Connected Devices Auto Setup\*'
            - 'c:\program files (x86)\Symantec\Network Connected Devices Auto Setup\*'
            - 'c:\windows\system32\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
