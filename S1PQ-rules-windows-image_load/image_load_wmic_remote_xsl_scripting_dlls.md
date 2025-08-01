```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (src.process.image.path contains "\wmic.exe" and (module.path contains "\jscript.dll" or module.path contains "\vbscript.dll")))
```


# Original Sigma Rule:
```yaml
title: WMIC Loading Scripting Libraries
id: 06ce37c2-61ab-4f05-9ff5-b1a96d18ae32
status: test
description: Detects threat actors proxy executing code and bypassing application controls by leveraging wmic and the `/FORMAT` argument switch to download and execute an XSL file (i.e js, vbs, etc).
references:
    - https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-201017061100.html
    - https://twitter.com/dez_/status/986614411711442944
    - https://lolbas-project.github.io/lolbas/Binaries/Wmic/
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-10-17
modified: 2022-10-13
tags:
    - attack.defense-evasion
    - attack.t1220
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\wmic.exe'
        ImageLoaded|endswith:
            - '\jscript.dll'
            - '\vbscript.dll'
    condition: selection
falsepositives:
    - The command wmic os get lastboottuptime loads vbscript.dll
    - The command wmic os get locale loads vbscript.dll
    - Since the ImageLoad event doesn't have enough information in this case. It's better to look at the recent process creation events that spawned the WMIC process and investigate the command line and parent/child processes to get more insights
level: medium
```
