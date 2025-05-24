```sql
// Translated content (automatically translated on 24-05-2025 01:24:03):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\opera_elf.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of opera_elf.dll
id: 3451113b-5254-48a3-5583-5b9ff8715208
status: experimental
description: Detects possible DLL hijacking of opera_elf.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/opera/opera_elf.html
author: "Wietze Beukema"
date: 2023-07-28
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\opera_elf.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=Opera Norway AS, O=Opera Norway AS, L=Oslo, S=Oslo, C=NO, SERIALNUMBER=916 368 127'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
