```sql
// Translated content (automatically translated on 29-11-2025 01:25:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\libxfont-1.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of libxfont-1.dll
id: 4954713b-9809-48a3-9172-5b9ff8180439
status: experimental
description: Detects possible DLL hijacking of libxfont-1.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/mobatek/libxfont-1.html
author: "Jai Minton - HuntressLabs"
date: 2024-05-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libxfont-1.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'C=FR, PostalCode=31830, S=Midi-Pyrénées, L=Plaisance du Touch, STREET=13 rue Paul Bernadot, O=Mobatek, CN=Mobatek'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
