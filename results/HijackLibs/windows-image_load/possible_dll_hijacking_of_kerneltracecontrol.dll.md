```sql
// Translated content (automatically translated on 10-09-2026 03:38:18):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\kerneltracecontrol.dll" and (not (module.path contains "c:\\program files\\ABBYY FineReader\\" or module.path contains "c:\\program files (x86)\\ABBYY FineReader\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of kerneltracecontrol.dll
id: 6685881b-5380-48a3-4616-5b9ff8707436
status: experimental
description: Detects possible DLL hijacking of kerneltracecontrol.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/abbyy/kerneltracecontrol.html
author: "Cristian Poenaru - HuntressLabs"
date: 2026-09-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\kerneltracecontrol.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\ABBYY FineReader\\*'
            - 'c:\program files (x86)\ABBYY FineReader\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
