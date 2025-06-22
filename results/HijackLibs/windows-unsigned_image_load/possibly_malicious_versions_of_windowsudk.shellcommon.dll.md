```sql
// Translated content (automatically translated on 22-06-2025 01:45:23):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\windowsudk.shellcommon.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of windowsudk.shellcommon.dll
id: 5019783b-2897-48a3-6541-5b9ff8831881
status: experimental
description: Detects possible DLL hijacking of windowsudk.shellcommon.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/windowsudk.shellcommon.html
author: "Wietze Beukema"
date: 2022-05-21
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\windowsudk.shellcommon.dll'
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
