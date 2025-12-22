```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\vftrace.dll" and (not (module.path in ("c:\\program files\\CyberArk\\Endpoint Privilege Manager\\Agent\\x32\*","c:\\program files (x86)\\CyberArk\\Endpoint Privilege Manager\\Agent\\x32\*","c:\\program files\\CyberArk\\Endpoint Privilege Manager\\Agent\\x64\*","c:\\program files (x86)\\CyberArk\\Endpoint Privilege Manager\\Agent\\x64\*","c:\\program files\\CyberArk\\Endpoint Privilege Manager\\Agent\*","c:\\program files (x86)\\CyberArk\\Endpoint Privilege Manager\\Agent\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vftrace.dll
id: 1895971b-7927-48a3-7311-5b9ff8937088
status: experimental
description: Detects possible DLL hijacking of vftrace.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/cyberark/vftrace.html
author: "Sorina Ionescu"
date: 2022-10-17
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vftrace.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\CyberArk\Endpoint Privilege Manager\Agent\x32\*'
            - 'c:\program files (x86)\CyberArk\Endpoint Privilege Manager\Agent\x32\*'
            - 'c:\program files\CyberArk\Endpoint Privilege Manager\Agent\x64\*'
            - 'c:\program files (x86)\CyberArk\Endpoint Privilege Manager\Agent\x64\*'
            - 'c:\program files\CyberArk\Endpoint Privilege Manager\Agent\*'
            - 'c:\program files (x86)\CyberArk\Endpoint Privilege Manager\Agent\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
