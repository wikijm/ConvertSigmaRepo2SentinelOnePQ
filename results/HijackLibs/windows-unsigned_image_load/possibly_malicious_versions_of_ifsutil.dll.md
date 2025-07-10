```sql
// Translated content (automatically translated on 10-07-2025 01:40:35):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\ifsutil.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of ifsutil.dll
id: 5896393b-2028-48a3-1241-5b9ff8689220
status: experimental
description: Detects possible DLL hijacking of ifsutil.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/ifsutil.html
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
        ImageLoaded: '*\ifsutil.dll'
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
