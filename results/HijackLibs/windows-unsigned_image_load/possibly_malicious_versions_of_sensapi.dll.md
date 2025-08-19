```sql
// Translated content (automatically translated on 19-08-2025 01:26:35):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\sensapi.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of sensapi.dll
id: 6628913b-8844-48a3-7027-5b9ff8114518
status: experimental
description: Detects possible DLL hijacking of sensapi.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/sensapi.html
author: "Wietze Beukema"
date: 2023-07-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\sensapi.dll'
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
