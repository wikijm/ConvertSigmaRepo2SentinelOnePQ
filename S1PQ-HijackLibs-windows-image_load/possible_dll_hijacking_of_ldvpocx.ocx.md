```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\ldvpocx.ocx" and (not (module.path in ("c:\program files\Symantec_Client_Security\Symantec AntiVirus\*","c:\program files (x86)\Symantec_Client_Security\Symantec AntiVirus\*","c:\program files\Symantec AntiVirus\*","c:\program files (x86)\Symantec AntiVirus\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of ldvpocx.ocx
id: 2888911b-2523-48a3-4236-5b9ff8872802
status: experimental
description: Detects possible DLL hijacking of ldvpocx.ocx by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/symantec/ldvpocx.html
author: "Wietze Beukema"
date: 2023-04-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\ldvpocx.ocx'
    filter:
        ImageLoaded:
            - 'c:\program files\Symantec_Client_Security\Symantec AntiVirus\*'
            - 'c:\program files (x86)\Symantec_Client_Security\Symantec AntiVirus\*'
            - 'c:\program files\Symantec AntiVirus\*'
            - 'c:\program files (x86)\Symantec AntiVirus\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
