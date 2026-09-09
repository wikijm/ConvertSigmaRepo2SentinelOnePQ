```sql
// Translated content (automatically translated on 09-09-2026 03:40:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\teamspeak_control.dll" and (not (module.path contains "c:\\program files\\Common Files\\Overwolf\\Teamspeak\\" or module.path contains "c:\\program files (x86)\\Common Files\\Overwolf\\Teamspeak\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of teamspeak_control.dll
id: 2800401b-8154-48a3-4104-5b9ff8248697
status: experimental
description: Detects possible DLL hijacking of teamspeak_control.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/overwolf/teamspeak_control.html
author: "Wietze Beukema"
date: 2026-06-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\teamspeak_control.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Common Files\Overwolf\Teamspeak\\*'
            - 'c:\program files (x86)\Common Files\Overwolf\Teamspeak\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
