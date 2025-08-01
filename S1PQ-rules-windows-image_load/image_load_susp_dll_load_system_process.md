```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (src.process.image.path contains "C:\Windows\" and (module.path contains "C:\Users\Public\" or module.path contains "C:\PerfLogs\")))
```


# Original Sigma Rule:
```yaml
title: DLL Load By System Process From Suspicious Locations
id: 9e9a9002-56c4-40fd-9eff-e4b09bfa5f6c
status: test
description: Detects when a system process (i.e. located in system32, syswow64, etc.) loads a DLL from a suspicious location or a location with permissive permissions such as "C:\Users\Public"
references:
    - https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC (Idea)
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-17
modified: 2023-09-18
tags:
    - attack.defense-evasion
    - attack.t1070
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|startswith: 'C:\Windows\'
        ImageLoaded|startswith:
            # TODO: Add more suspicious paths as you see fit in your env
            - 'C:\Users\Public\'
            - 'C:\PerfLogs\'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
