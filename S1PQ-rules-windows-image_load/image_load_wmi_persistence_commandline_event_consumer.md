```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (src.process.image.path="C:\Windows\System32\wbem\WmiPrvSE.exe" and module.path contains "\wbemcons.dll"))
```


# Original Sigma Rule:
```yaml
title: WMI Persistence - Command Line Event Consumer
id: 05936ce2-ee05-4dae-9d03-9a391cf2d2c6
status: test
description: Detects WMI command line event consumers
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018-03-07
modified: 2021-11-27
tags:
    - attack.t1546.003
    - attack.persistence
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image: 'C:\Windows\System32\wbem\WmiPrvSE.exe'
        ImageLoaded|endswith: '\wbemcons.dll'
    condition: selection
falsepositives:
    - Unknown (data set is too small; further testing needed)
level: high
```
