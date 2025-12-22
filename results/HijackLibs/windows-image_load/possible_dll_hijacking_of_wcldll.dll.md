```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\wcldll.dll" and (not (module.path in ("c:\\program files\\Cisco Systems\\Cisco Jabber\*","c:\\program files (x86)\\Cisco Systems\\Cisco Jabber\*","c:\\program files\\Webex\\Applications\*","c:\\program files (x86)\\Webex\\Applications\*","c:\\program files\\Webex\\Plugins\*","c:\\program files (x86)\\Webex\\Plugins\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wcldll.dll
id: 7641611b-9521-48a3-3514-5b9ff8984964
status: experimental
description: Detects possible DLL hijacking of wcldll.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/cisco/wcldll.html
author: "Jai Minton - HuntressLabs"
date: 2024-04-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wcldll.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Cisco Systems\Cisco Jabber\*'
            - 'c:\program files (x86)\Cisco Systems\Cisco Jabber\*'
            - 'c:\program files\Webex\Applications\*'
            - 'c:\program files (x86)\Webex\Applications\*'
            - 'c:\program files\Webex\Plugins\*'
            - 'c:\program files (x86)\Webex\Plugins\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
