```sql
// Translated content (automatically translated on 15-09-2025 01:25:37):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\msasn1.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of msasn1.dll
id: 5593413b-7568-48a3-5988-5b9ff8497391
status: experimental
description: Detects possible DLL hijacking of msasn1.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/msasn1.html
author: "ice-wzl"
date: 2025-04-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\msasn1.dll'
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
