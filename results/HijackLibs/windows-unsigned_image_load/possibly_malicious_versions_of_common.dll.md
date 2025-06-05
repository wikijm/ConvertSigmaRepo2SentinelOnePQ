```sql
// Translated content (automatically translated on 05-06-2025 01:27:46):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\common.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of common.dll
id: 1355323b-4266-48a3-3778-5b9ff8480154
status: experimental
description: Detects possible DLL hijacking of common.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/iroot/common.html
author: "Jai Minton"
date: 2025-05-05
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\common.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=WoSign Time Stamping Signer,O=WoSign CA Limited,C=CN'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
