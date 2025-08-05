```sql
// Translated content (automatically translated on 05-08-2025 01:49:11):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\aclui.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of aclui.dll
id: 6961133b-1313-48a3-6160-5b9ff8597384
status: experimental
description: Detects possible DLL hijacking of aclui.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/aclui.html
author: "Wietze Beukema"
date: 2021-12-07
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\aclui.dll'
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
