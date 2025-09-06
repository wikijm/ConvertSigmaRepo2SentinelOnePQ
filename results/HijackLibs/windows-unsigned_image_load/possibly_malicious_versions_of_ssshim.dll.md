```sql
// Translated content (automatically translated on 06-09-2025 01:18:44):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\ssshim.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of ssshim.dll
id: 6777393b-5805-48a3-6769-5b9ff8479266
status: experimental
description: Detects possible DLL hijacking of ssshim.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/ssshim.html
author: "Wietze Beukema"
date: 2021-02-28
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\ssshim.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
