```sql
// Translated content (automatically translated on 29-11-2025 01:25:34):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\x32bridge.dll")
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of x32bridge.dll
id: 1216793b-9223-48a3-6181-5b9ff8946663
status: experimental
description: Detects possible DLL hijacking of x32bridge.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/x64dbg/x32bridge.html
author: "Wietze Beukema"
date: 2023-03-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\x32bridge.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=Duncan Ogilvie, O=Duncan Ogilvie, L=Wrocław, S=Dolnośląskie, C=PL'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
