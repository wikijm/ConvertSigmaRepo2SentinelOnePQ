```sql
// Translated content (automatically translated on 01-03-2026 02:34:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\jrtools.dll" and (not (module.path="c:\\program files\\J River\\Media Center *\\*" or module.path="c:\\program files (x86)\\J River\\Media Center *\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of jrtools.dll
id: 3986951b-1497-48a3-1258-5b9ff8247078
status: experimental
description: Detects possible DLL hijacking of jrtools.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/jriver/jrtools.html
author: "Rick Gatenby"
date: 2026-02-03
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\jrtools.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\J River\Media Center *\\*'
            - 'c:\program files (x86)\J River\Media Center *\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
