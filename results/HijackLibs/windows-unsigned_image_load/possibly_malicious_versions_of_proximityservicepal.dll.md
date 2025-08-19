```sql
// Translated content (automatically translated on 19-08-2025 01:26:35):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\proximityservicepal.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of proximityservicepal.dll
id: 9554353b-7437-48a3-2115-5b9ff8177990
status: experimental
description: Detects possible DLL hijacking of proximityservicepal.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/proximityservicepal.html
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
        ImageLoaded: '*\proximityservicepal.dll'
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
