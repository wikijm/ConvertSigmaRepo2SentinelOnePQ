```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\siteadv.dll" and (not (module.path in ("c:\program files\SiteAdvisor\*\*","c:\program files (x86)\SiteAdvisor\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of siteadv.dll
id: 1129001b-5201-48a3-9406-5b9ff8493552
status: experimental
description: Detects possible DLL hijacking of siteadv.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mcafee/siteadv.html
author: "Christiaan Beek"
date: 2023-01-16
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\siteadv.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\SiteAdvisor\*\*'
            - 'c:\program files (x86)\SiteAdvisor\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
