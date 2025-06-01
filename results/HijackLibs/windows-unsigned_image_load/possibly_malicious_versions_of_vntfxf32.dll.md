```sql
// Translated content (automatically translated on 01-06-2025 01:51:33):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\vntfxf32.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of vntfxf32.dll
id: 5845123b-4150-48a3-8413-5b9ff8327495
status: experimental
description: Detects possible DLL hijacking of vntfxf32.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/ventafax/vntfxf32.html
author: "Wietze Beukema"
date: 2023-04-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vntfxf32.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'C=RU, ST=St. Petersburg, L=St. Petersburg, O=Venta Association, OU=Digital ID Class 3 - Microsoft Software Validation v2, CN=Venta Association'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
