```sql
// Translated content (automatically translated on 08-06-2025 01:26:24):
event.type="ModuleLoad" and (endpoint.os="windows" and ((src.process.image.path contains "\fxssvc.exe" and module.path contains "ualapi.dll") and (not module.path contains "C:\Windows\WinSxS\")))
```


# Original Sigma Rule:
```yaml
title: Fax Service DLL Search Order Hijack
id: 828af599-4c53-4ed2-ba4a-a9f835c434ea
status: test
description: The Fax service attempts to load ualapi.dll, which is non-existent. An attacker can then (side)load their own malicious DLL using this service.
references:
    - https://windows-internals.com/faxing-your-way-to-system/
author: NVISO
date: 2020-05-04
modified: 2022-06-02
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\fxssvc.exe'
        ImageLoaded|endswith: 'ualapi.dll'
    filter:
        ImageLoaded|startswith: 'C:\Windows\WinSxS\'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
```
