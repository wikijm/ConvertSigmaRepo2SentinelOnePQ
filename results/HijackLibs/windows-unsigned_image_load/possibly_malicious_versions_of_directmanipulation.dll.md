```sql
// Translated content (automatically translated on 07-05-2025 01:26:21):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\directmanipulation.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of directmanipulation.dll
id: 5855903b-3713-48a3-9900-5b9ff8898085
status: experimental
description: Detects possible DLL hijacking of directmanipulation.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/directmanipulation.html
author: "Wietze Beukema"
date: 2022-08-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\directmanipulation.dll'
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
