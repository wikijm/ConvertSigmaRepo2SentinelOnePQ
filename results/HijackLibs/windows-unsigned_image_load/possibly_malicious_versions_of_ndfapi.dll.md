```sql
// Translated content (automatically translated on 08-05-2025 01:26:27):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\ndfapi.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of ndfapi.dll
id: 6612643b-9395-48a3-4833-5b9ff8882182
status: experimental
description: Detects possible DLL hijacking of ndfapi.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/ndfapi.html
author: "Wietze Beukema"
date: 2021-02-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\ndfapi.dll'
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
