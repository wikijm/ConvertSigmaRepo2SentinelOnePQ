```sql
// Translated content (automatically translated on 02-06-2025 01:40:20):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\vivaldi_elf.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of vivaldi_elf.dll
id: 5086083b-2523-48a3-4236-5b9ff8819409
status: experimental
description: Detects possible DLL hijacking of vivaldi_elf.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/vivaldi/vivaldi_elf.html
author: "Wietze Beukema"
date: 2023-04-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vivaldi_elf.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'serialNumber=912 309 975, C=NO, ST=Oslo, L=Oslo, street=Mølleparken 6, O=Vivaldi Technologies AS, CN=Vivaldi Technologies AS'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
