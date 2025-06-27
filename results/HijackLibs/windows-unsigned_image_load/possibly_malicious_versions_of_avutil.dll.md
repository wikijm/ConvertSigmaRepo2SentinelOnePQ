```sql
// Translated content (automatically translated on 27-06-2025 01:39:09):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\avutil.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of avutil.dll
id: 4821733b-3109-48a3-1955-5b9ff8677522
status: experimental
description: Detects possible DLL hijacking of avutil.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/vsosoftware/avutil.html
author: "Wietze Beukema"
date: 2024-07-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\avutil.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=VSO Software SARL, O=VSO Software SARL, L=Toulouse, S=Midi-Pyrenees, C=FR'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
