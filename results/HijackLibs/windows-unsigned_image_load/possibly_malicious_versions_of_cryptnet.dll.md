```sql
// Translated content (automatically translated on 04-05-2025 01:40:39):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\cryptnet.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of cryptnet.dll
id: 6024933b-8091-48a3-6555-5b9ff8476279
status: experimental
description: Detects possible DLL hijacking of cryptnet.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/cryptnet.html
author: "Will Summerhill"
date: 2024-11-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\cryptnet.dll'
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
