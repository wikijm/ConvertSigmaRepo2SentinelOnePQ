```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\ciscosparklauncher.dll" and (not (module.path in ("c:\\users\*\\appdata\\local\\CiscoSparkLauncher\*","c:\\users\*\\appdata\\local\\Programs\\Cisco Spark\*","c:\\program files\\Cisco Spark\*","c:\\program files (x86)\\Cisco Spark\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of ciscosparklauncher.dll
id: 1830021b-6060-48a3-8680-5b9ff8293352
status: experimental
description: Detects possible DLL hijacking of ciscosparklauncher.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/cisco/ciscosparklauncher.html
author: "Sorina Ionescu"
date: 2022-10-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\ciscosparklauncher.dll'
    filter:
        ImageLoaded:
            - 'c:\users\*\appdata\local\CiscoSparkLauncher\*'
            - 'c:\users\*\appdata\local\Programs\Cisco Spark\*'
            - 'c:\program files\Cisco Spark\*'
            - 'c:\program files (x86)\Cisco Spark\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
