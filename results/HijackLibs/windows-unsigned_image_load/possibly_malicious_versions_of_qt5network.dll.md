```sql
// Translated content (automatically translated on 02-08-2025 01:41:33):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\qt5network.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of qt5network.dll
id: 9190193b-7904-48a3-3158-5b9ff8134247
status: experimental
description: Detects possible DLL hijacking of qt5network.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/qt/qt5network.html
author: "Jai Minton"
date: 2025-05-09
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\qt5network.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=Symantec Time Stamping Services CA - G2,O=Symantec Corporation,C=US'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
