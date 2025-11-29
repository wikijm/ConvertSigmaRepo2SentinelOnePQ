```sql
// Translated content (automatically translated on 29-11-2025 01:25:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\appwiz.cpl" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of appwiz.cpl
id: 9483913b-8657-48a3-9976-5b9ff8530009
status: experimental
description: Detects possible DLL hijacking of appwiz.cpl by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/appwiz.html
author: "Wietze Beukema"
date: 2024-01-11
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\appwiz.cpl'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
