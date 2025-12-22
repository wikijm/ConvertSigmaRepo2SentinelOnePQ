```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\epnsm.dll" and (not (module.path in ("c:\\program files\\Epson Software\\Document Capture Server\*","c:\\program files (x86)\\Epson Software\\Document Capture Server\*","c:\\program files\\Epson Software\\Event Manager\*","c:\\program files (x86)\\Epson Software\\Event Manager\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of epnsm.dll
id: 7315301b-9675-48a3-8026-5b9ff8960613
status: experimental
description: Detects possible DLL hijacking of epnsm.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/seiko/epnsm.html
author: "Jai Minton"
date: 2025-05-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\epnsm.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Epson Software\Document Capture Server\*'
            - 'c:\program files (x86)\Epson Software\Document Capture Server\*'
            - 'c:\program files\Epson Software\Event Manager\*'
            - 'c:\program files (x86)\Epson Software\Event Manager\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
