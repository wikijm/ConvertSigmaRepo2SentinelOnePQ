```sql
// Translated content (automatically translated on 10-02-2026 02:38:31):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\libngs.dll" and (not (module.path contains "c:\\program files\\Sangfor\\SSL\\RemoteAppClient\\" or module.path contains "c:\\program files (x86)\\Sangfor\\SSL\\RemoteAppClient\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libngs.dll
id: 5819401b-5039-48a3-6342-5b9ff8298918
status: experimental
description: Detects possible DLL hijacking of libngs.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/sangfor/libngs.html
author: "Swachchhanda Shrawan Poudel"
date: 2026-01-28
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libngs.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Sangfor\SSL\RemoteAppClient\\*'
            - 'c:\program files (x86)\Sangfor\SSL\RemoteAppClient\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
