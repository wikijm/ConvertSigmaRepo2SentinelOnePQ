```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\fnp_act_installer.dll" and (not (module.path in ("c:\program files\InstallShield\*\System\*","c:\program files (x86)\InstallShield\*\System\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of fnp_act_installer.dll
id: 8169621b-9569-48a3-1936-5b9ff8218064
status: experimental
description: Detects possible DLL hijacking of fnp_act_installer.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/flexera/fnp_act_installer.html
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
        ImageLoaded: '*\fnp_act_installer.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\InstallShield\*\System\*'
            - 'c:\program files (x86)\InstallShield\*\System\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
