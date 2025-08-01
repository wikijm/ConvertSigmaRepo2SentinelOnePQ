```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (src.process.image.path contains "\wmiprvse.exe" and module.path contains "\wbem\wbemcomn.dll"))
```


# Original Sigma Rule:
```yaml
title: Wmiprvse Wbemcomn DLL Hijack
id: 7707a579-e0d8-4886-a853-ce47e4575aaa
status: test
description: Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network and loading it for a WMI DLL Hijack scenario.
references:
    - https://threathunterplaybook.com/hunts/windows/201009-RemoteWMIWbemcomnDLLHijack/notebook.html
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-10-12
modified: 2022-10-09
tags:
    - attack.execution
    - attack.t1047
    - attack.lateral-movement
    - attack.t1021.002
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|endswith: '\wmiprvse.exe'
        ImageLoaded|endswith: '\wbem\wbemcomn.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
```
