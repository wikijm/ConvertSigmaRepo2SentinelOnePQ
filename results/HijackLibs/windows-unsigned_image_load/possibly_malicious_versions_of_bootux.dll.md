```sql
// Translated content (automatically translated on 22-05-2025 01:26:48):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\bootux.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of bootux.dll
id: 3253143b-2028-48a3-1241-5b9ff8137525
status: experimental
description: Detects possible DLL hijacking of bootux.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/bootux.html
author: "Chris Spehn"
date: 2021-08-16
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\bootux.dll'
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
