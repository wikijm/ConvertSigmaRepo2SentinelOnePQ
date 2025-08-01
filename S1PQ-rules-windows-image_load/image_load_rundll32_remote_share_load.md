```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (src.process.image.path contains "\rundll32.exe" and module.path contains "\\"))
```


# Original Sigma Rule:
```yaml
title: Remote DLL Load Via Rundll32.EXE
id: f40017b3-cb2e-4335-ab5d-3babf679c1de
status: test
description: Detects a remote DLL load event via "rundll32.exe".
references:
    - https://github.com/gabe-k/themebleed
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-09-18
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        ImageLoaded|startswith: '\\\\'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
