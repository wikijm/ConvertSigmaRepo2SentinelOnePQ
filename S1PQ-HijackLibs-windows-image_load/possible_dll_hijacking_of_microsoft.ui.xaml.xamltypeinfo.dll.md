```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\microsoft.ui.xaml.xamltypeinfo.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of microsoft.ui.xaml.xamltypeinfo.dll
id: 3584231b-7740-48a3-2257-5b9ff8497102
status: experimental
description: Detects possible DLL hijacking of microsoft.ui.xaml.xamltypeinfo.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/microsoft.ui.xaml.xamltypeinfo.html
author: "Wietze Beukema"
date: 2023-04-03
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\microsoft.ui.xaml.xamltypeinfo.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
