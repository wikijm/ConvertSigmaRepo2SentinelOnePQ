```sql
// Translated content (automatically translated on 21-08-2025 01:24:03):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\rcdll.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of rcdll.dll
id: 1324853b-2811-48a3-1599-5b9ff8815748
status: experimental
description: Detects possible DLL hijacking of rcdll.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/external/rcdll.html
author: "Gary Lobermier"
date: 2023-05-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\rcdll.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
