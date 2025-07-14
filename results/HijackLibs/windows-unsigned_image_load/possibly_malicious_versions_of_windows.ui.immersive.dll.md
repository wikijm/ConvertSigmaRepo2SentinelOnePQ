```sql
// Translated content (automatically translated on 14-07-2025 01:46:18):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\windows.ui.immersive.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of windows.ui.immersive.dll
id: 1638673b-2028-48a3-1241-5b9ff8322645
status: experimental
description: Detects possible DLL hijacking of windows.ui.immersive.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/windows.ui.immersive.html
author: "Chris Spehn"
date: 2021-08-16
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\windows.ui.immersive.dll'
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
