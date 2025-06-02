```sql
// Translated content (automatically translated on 02-06-2025 01:40:20):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\smadhook32c.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of smadhook32c.dll
id: 3416183b-4150-48a3-8413-5b9ff8316275
status: experimental
description: Detects possible DLL hijacking of smadhook32c.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/smadav/smadhook32c.html
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
        ImageLoaded: '*\smadhook32c.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'C=ID, L=Palangkaraya, O=Zainuddin Nafarin, CN=Zainuddin Nafarin'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
