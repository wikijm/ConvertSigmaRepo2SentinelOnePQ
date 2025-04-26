```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\mimetools.dll" and (not (module.path in ("c:\program files\Notepad++\plugins\*","c:\program files (x86)\Notepad++\plugins\*","c:\program files\Notepad++\plugins\mimetools\*","c:\program files (x86)\Notepad++\plugins\mimetools\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mimetools.dll
id: 2659501b-9425-48a3-2496-5b9ff8181535
status: experimental
description: Detects possible DLL hijacking of mimetools.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/notepad++/mimetools.html
author: "Wietze Beukema"
date: 2024-03-31
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mimetools.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Notepad++\plugins\*'
            - 'c:\program files (x86)\Notepad++\plugins\*'
            - 'c:\program files\Notepad++\plugins\mimetools\*'
            - 'c:\program files (x86)\Notepad++\plugins\mimetools\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
