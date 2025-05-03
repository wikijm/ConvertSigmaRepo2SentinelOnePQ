```sql
// Translated content (automatically translated on 03-05-2025 01:23:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\textshaping.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of textshaping.dll
id: 3832043b-2811-48a3-1599-5b9ff8887640
status: experimental
description: Detects possible DLL hijacking of textshaping.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/textshaping.html
author: "Gary Lobermier"
date: 2023-05-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\textshaping.dll'
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
