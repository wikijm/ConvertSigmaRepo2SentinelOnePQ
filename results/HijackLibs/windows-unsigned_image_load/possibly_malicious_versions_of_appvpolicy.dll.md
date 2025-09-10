```sql
// Translated content (automatically translated on 10-09-2025 01:19:45):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\appvpolicy.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of appvpolicy.dll
id: 5334353b-2028-48a3-1241-5b9ff8107382
status: experimental
description: Detects possible DLL hijacking of appvpolicy.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/appvpolicy.html
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
        ImageLoaded: '*\appvpolicy.dll'
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
