```sql
// Translated content (automatically translated on 13-02-2026 02:32:00):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\log.dll" and (not (module.path in ("c:\\program files\\Bitdefender Antivirus Free\*","c:\\program files (x86)\\Bitdefender Antivirus Free\*","c:\\program files\\Bitdefender Agent\*\*","c:\\program files (x86)\\Bitdefender Agent\*\*","c:\\program files\\Bitdefender Agent\*\\x64\*","c:\\program files (x86)\\Bitdefender Agent\*\\x64\*","c:\\program files\\Bitdefender\\Bitdefender Security\*","c:\\program files (x86)\\Bitdefender\\Bitdefender Security\*","c:\\program files\\Bitdefender\\Bitdefender Security App\*","c:\\program files (x86)\\Bitdefender\\Bitdefender Security App\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of log.dll
id: 9451181b-1318-48a3-1317-5b9ff8166908
status: experimental
description: Detects possible DLL hijacking of log.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/bitdefender/log.html
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
        ImageLoaded: '*\log.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Bitdefender Antivirus Free\*'
            - 'c:\program files (x86)\Bitdefender Antivirus Free\*'
            - 'c:\program files\Bitdefender Agent\*\*'
            - 'c:\program files (x86)\Bitdefender Agent\*\*'
            - 'c:\program files\Bitdefender Agent\*\x64\*'
            - 'c:\program files (x86)\Bitdefender Agent\*\x64\*'
            - 'c:\program files\Bitdefender\Bitdefender Security\*'
            - 'c:\program files (x86)\Bitdefender\Bitdefender Security\*'
            - 'c:\program files\Bitdefender\Bitdefender Security App\*'
            - 'c:\program files (x86)\Bitdefender\Bitdefender Security App\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
