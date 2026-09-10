```sql
// Translated content (automatically translated on 10-09-2026 03:38:18):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\dsp_ippv2_x64.dll" and (not (module.path="c:\\program files\\ABBYY FineReader *\\*" or module.path="c:\\program files (x86)\\ABBYY FineReader *\\*" or module.path="c:\\program files\\Image-Line\\FL Studio *\\Shared\\*" or module.path="c:\\program files (x86)\\Image-Line\\FL Studio *\\Shared\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dsp_ippv2_x64.dll
id: 8624041b-3513-48a3-4540-5b9ff8328618
status: experimental
description: Detects possible DLL hijacking of dsp_ippv2_x64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/abbyy/dsp_ippv2_x64.html
author: "Wietze Beukema"
date: 2026-09-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\dsp_ippv2_x64.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\ABBYY FineReader *\\*'
            - 'c:\program files (x86)\ABBYY FineReader *\\*'
            - 'c:\program files\Image-Line\FL Studio *\Shared\\*'
            - 'c:\program files (x86)\Image-Line\FL Studio *\Shared\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
