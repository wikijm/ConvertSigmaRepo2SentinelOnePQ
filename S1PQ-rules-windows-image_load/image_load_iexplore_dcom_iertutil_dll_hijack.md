```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (src.process.image.path contains "\Internet Explorer\iexplore.exe" and module.path contains "\Internet Explorer\iertutil.dll"))
```


# Original Sigma Rule:
```yaml
title: Potential DCOM InternetExplorer.Application DLL Hijack - Image Load
id: f354eba5-623b-450f-b073-0b5b2773b6aa
related:
    - id: e554f142-5cf3-4e55-ace9-a1b59e0def65
      type: obsolete
    - id: 2f7979ae-f82b-45af-ac1d-2b10e93b0baa
      type: similar
status: test
description: Detects potential DLL hijack of "iertutil.dll" found in the DCOM InternetExplorer.Application Class
references:
    - https://threathunterplaybook.com/hunts/windows/201009-RemoteDCOMIErtUtilDLLHijack/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR), wagga
date: 2020-10-12
modified: 2022-12-18
tags:
    - attack.lateral-movement
    - attack.t1021.002
    - attack.t1021.003
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|endswith: '\Internet Explorer\iexplore.exe'
        ImageLoaded|endswith: '\Internet Explorer\iertutil.dll'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
