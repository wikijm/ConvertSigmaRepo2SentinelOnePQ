```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\libvlc.dll" and (not (module.path in ("c:\\program files\\VideoLAN\\VLC\*","c:\\program files (x86)\\VideoLAN\\VLC\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libvlc.dll
id: 1010921b-1035-48a3-1344-5b9ff8330336
status: experimental
description: Detects possible DLL hijacking of libvlc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/vlc/libvlc.html
author: "Wietze Beukema"
date: 2022-11-18
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libvlc.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\VideoLAN\VLC\*'
            - 'c:\program files (x86)\VideoLAN\VLC\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
