```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\mfdetours.dll" and (not module.path contains ":\Program Files (x86)\Windows Kits\10\bin\")))
```


# Original Sigma Rule:
```yaml
title: Potential Mfdetours.DLL Sideloading
id: d2605a99-2218-4894-8fd3-2afb7946514d
status: test
description: Detects potential DLL sideloading of "mfdetours.dll". While using "mftrace.exe" it can be abused to attach to an arbitrary process and force load any DLL named "mfdetours.dll" from the current directory of execution.
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-03
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\mfdetours.dll'
    filter_main_legit_path:
        ImageLoaded|contains: ':\Program Files (x86)\Windows Kits\10\bin\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: medium
```
