```sql
// Translated content (automatically translated on 07-09-2026 03:30:29):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\systemsettings.dll" and (not (module.path contains "C:\\Windows\\ImmersiveControlPanel\\" or module.path contains "C:\\Windows\\WinSxS\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of systemsettings.dll
id: 1360601b-8250-48a3-4063-5b9ff8296247
status: experimental
description: Detects possible DLL hijacking of systemsettings.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/systemsettings.html
author: "Daniel Koifman"
date: 2026-06-24
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\systemsettings.dll'
    filter:
        ImageLoaded:
            - 'C:\Windows\ImmersiveControlPanel\\*'
            - 'C:\Windows\WinSxS\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
