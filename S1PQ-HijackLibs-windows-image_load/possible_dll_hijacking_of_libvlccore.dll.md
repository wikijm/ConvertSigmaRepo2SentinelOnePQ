```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\libvlccore.dll" and (not (module.path in ("c:\program files\VideoLAN\VLC\*","c:\program files (x86)\VideoLAN\VLC\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libvlccore.dll
id: 3125661b-9569-48a3-1936-5b9ff8347377
status: experimental
description: Detects possible DLL hijacking of libvlccore.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/vlc/libvlccore.html
author: "Jai Minton - HuntressLabs"
date: 2024-04-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libvlccore.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\VideoLAN\VLC\*'
            - 'c:\program files (x86)\VideoLAN\VLC\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
