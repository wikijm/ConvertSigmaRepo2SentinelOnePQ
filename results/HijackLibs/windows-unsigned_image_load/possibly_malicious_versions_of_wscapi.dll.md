```sql
// Translated content (automatically translated on 30-06-2025 01:43:23):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\wscapi.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of wscapi.dll
id: 2593903b-7437-48a3-2115-5b9ff8485573
status: experimental
description: Detects possible DLL hijacking of wscapi.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/wscapi.html
author: "Chris Spehn"
date: 2021-08-17
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wscapi.dll'
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
