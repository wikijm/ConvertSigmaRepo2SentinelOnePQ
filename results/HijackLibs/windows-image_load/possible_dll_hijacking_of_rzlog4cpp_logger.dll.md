```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\rzlog4cpp_logger.dll" and (not module.path="c:\users\*\appdata\local\razer\InGameEngine\cache\RzFpsApplet\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of rzlog4cpp_logger.dll
id: 3158221b-7740-48a3-2257-5b9ff8164996
status: experimental
description: Detects possible DLL hijacking of rzlog4cpp_logger.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/razer/rzlog4cpp_logger.html
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
        ImageLoaded: '*\rzlog4cpp_logger.dll'
    filter:
        ImageLoaded:
            - 'c:\users\*\appdata\local\razer\InGameEngine\cache\RzFpsApplet\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
