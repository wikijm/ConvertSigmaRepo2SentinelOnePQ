```sql
// Translated content (automatically translated on 26-08-2025 01:25:32):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\symsrv.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of symsrv.dll
id: 9816233b-2811-48a3-1599-5b9ff8945318
status: experimental
description: Detects possible DLL hijacking of symsrv.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/external/symsrv.html
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
        ImageLoaded: '*\symsrv.dll'
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
