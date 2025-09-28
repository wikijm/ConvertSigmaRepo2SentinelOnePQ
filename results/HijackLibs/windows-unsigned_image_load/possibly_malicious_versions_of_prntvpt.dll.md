```sql
// Translated content (automatically translated on 28-09-2025 01:28:36):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\prntvpt.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of prntvpt.dll
id: 4968093b-7437-48a3-2115-5b9ff8372638
status: experimental
description: Detects possible DLL hijacking of prntvpt.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/prntvpt.html
author: "Chris Spehn"
date: 2021-08-17
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\prntvpt.dll'
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
