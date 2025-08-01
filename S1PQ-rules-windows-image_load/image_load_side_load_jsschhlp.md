```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\JSESPR.dll" and (not module.path contains "C:\Program Files\Common Files\Justsystem\JsSchHlp\")))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Via JsSchHlp
id: 68654bf0-4412-43d5-bfe8-5eaa393cd939
status: test
description: Detects potential DLL sideloading using JUSTSYSTEMS Japanese word processor
references:
    - https://www.welivesecurity.com/2022/12/14/unmasking-mirrorface-operation-liberalface-targeting-japanese-political-entities/
    - http://www.windowexe.com/bbs/board.php?q=jsschhlp-exe-c-program-files-common-files-justsystem-jsschhlp-jsschhlp
author: frack113
date: 2022-12-14
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\JSESPR.dll'
    filter:
        ImageLoaded|startswith: 'C:\Program Files\Common Files\Justsystem\JsSchHlp\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
