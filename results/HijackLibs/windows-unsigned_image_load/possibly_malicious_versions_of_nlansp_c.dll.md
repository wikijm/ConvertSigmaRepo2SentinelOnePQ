```sql
// Translated content (automatically translated on 14-06-2025 01:26:17):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\nlansp_c.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of nlansp_c.dll
id: 6274253b-2897-48a3-6541-5b9ff8652244
status: experimental
description: Detects possible DLL hijacking of nlansp_c.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/nlansp_c.html
author: "Wietze Beukema"
date: 2022-05-21
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\nlansp_c.dll'
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
