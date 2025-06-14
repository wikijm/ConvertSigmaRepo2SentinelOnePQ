```sql
// Translated content (automatically translated on 14-06-2025 01:26:17):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\epnsm.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of epnsm.dll
id: 7315303b-9675-48a3-8026-5b9ff8960613
status: experimental
description: Detects possible DLL hijacking of epnsm.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/seiko/epnsm.html
author: "Jai Minton"
date: 2025-05-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\epnsm.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=SEIKO EPSON CORPORATION,O=SEIKO EPSON CORPORATION,L=Suwa-Shi,ST=Nagano,C=JP'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
