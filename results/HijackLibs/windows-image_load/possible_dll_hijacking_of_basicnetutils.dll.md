```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\basicnetutils.dll" and (not (module.path in ("c:\users\*\appdata\local\Temp\*\Application2\*","c:\program files\BAIDU\BAIDUPINYIN\*\*","c:\program files (x86)\BAIDU\BAIDUPINYIN\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of basicnetutils.dll
id: 8230311b-8028-48a3-7945-5b9ff8500209
status: experimental
description: Detects possible DLL hijacking of basicnetutils.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/baidu/basicnetutils.html
author: "Wietze Beukema"
date: 2023-05-03
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\basicnetutils.dll'
    filter:
        ImageLoaded:
            - 'c:\users\*\appdata\local\Temp\*\Application2\*'
            - 'c:\program files\BAIDU\BAIDUPINYIN\*\*'
            - 'c:\program files (x86)\BAIDU\BAIDUPINYIN\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
