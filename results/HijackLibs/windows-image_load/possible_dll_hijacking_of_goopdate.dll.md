```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\goopdate.dll" and (not (module.path in ("c:\program files\Dropbox\Update\*","c:\program files (x86)\Dropbox\Update\*","c:\program files\Dropbox\Update\*\*","c:\program files (x86)\Dropbox\Update\*\*","c:\users\*\appdata\local\DropboxUpdate\Update\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of goopdate.dll
id: 8106291b-1674-48a3-4587-5b9ff8794453
status: experimental
description: Detects possible DLL hijacking of goopdate.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/dropbox/goopdate.html
author: "Jai Minton - HuntressLabs"
date: 2024-08-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\goopdate.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Dropbox\Update\*'
            - 'c:\program files (x86)\Dropbox\Update\*'
            - 'c:\program files\Dropbox\Update\*\*'
            - 'c:\program files (x86)\Dropbox\Update\*\*'
            - 'c:\users\*\appdata\local\DropboxUpdate\Update\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
