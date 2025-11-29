```sql
// Translated content (automatically translated on 29-11-2025 01:25:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\facesdk.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of facesdk.dll
id: 4818683b-4150-48a3-8413-5b9ff8954421
status: experimental
description: Detects possible DLL hijacking of facesdk.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/luxand/facesdk.html
author: "Wietze Beukema"
date: 2023-04-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\facesdk.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'C=US, ST=Virginia, L=Alexandria, O=''Luxand, Inc.'', CN=''Luxand, Inc.'''

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
