```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\flutter_gpu_texture_renderer_plugin.dll" and (not (module.path in ("c:\\users\*\\appdata\\local\\rustdesk\*","c:\\program files\\RustDesk\*","c:\\program files (x86)\\RustDesk\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of flutter_gpu_texture_renderer_plugin.dll
id: 7010851b-8907-48a3-9464-5b9ff8471033
status: experimental
description: Detects possible DLL hijacking of flutter_gpu_texture_renderer_plugin.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/rustdesk/flutter_gpu_texture_renderer_plugin.html
author: "Wietze Beukema"
date: 2025-02-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\flutter_gpu_texture_renderer_plugin.dll'
    filter:
        ImageLoaded:
            - 'c:\users\*\appdata\local\rustdesk\*'
            - 'c:\program files\RustDesk\*'
            - 'c:\program files (x86)\RustDesk\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
