```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\libvlc.dll" and (not (module.path contains "C:\Program Files (x86)\VideoLAN\VLC\" or module.path contains "C:\Program Files\VideoLAN\VLC\"))))
```


# Original Sigma Rule:
```yaml
title: Potential Libvlc.DLL Sideloading
id: bf9808c4-d24f-44a2-8398-b65227d406b6
status: test
description: Detects potential DLL sideloading of "libvlc.dll", a DLL that is legitimately used by "VLC.exe"
references:
    - https://www.trendmicro.com/en_us/research/23/c/earth-preta-updated-stealthy-strategies.html
    - https://hijacklibs.net/entries/3rd_party/vlc/libvlc.html
author: X__Junior
date: 2023-04-17
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\libvlc.dll'
    filter_main_vlc:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\VideoLAN\VLC\'
            - 'C:\Program Files\VideoLAN\VLC\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - False positives are expected if VLC is installed in non-default locations
level: medium
```
