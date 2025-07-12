```sql
// Translated content (automatically translated on 12-07-2025 01:43:11):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\dbgmodel.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of dbgmodel.dll
id: 1149383b-2811-48a3-1599-5b9ff8991076
status: experimental
description: Detects possible DLL hijacking of dbgmodel.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/dbgmodel.html
author: "Gary Lobermier"
date: 2023-05-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\dbgmodel.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
