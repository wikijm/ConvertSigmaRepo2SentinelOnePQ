```sql
// Translated content (automatically translated on 29-11-2025 01:25:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\tmdbg64.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of tmdbg64.dll
id: 9722623b-9632-48a3-5733-5b9ff8437989
status: experimental
description: Detects possible DLL hijacking of tmdbg64.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/trendmicro/tmdbg64.html
author: "Still Hsu"
date: 2025-11-05
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tmdbg64.dll'
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
