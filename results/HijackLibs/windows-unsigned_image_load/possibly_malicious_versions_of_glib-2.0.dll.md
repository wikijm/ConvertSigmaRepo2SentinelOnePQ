```sql
// Translated content (automatically translated on 11-07-2025 01:41:43):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\glib-2.0.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of glib-2.0.dll
id: 7524133b-7740-48a3-2257-5b9ff8783090
status: experimental
description: Detects possible DLL hijacking of glib-2.0.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/vmware/glib-2.0.html
author: "Wietze Beukema"
date: 2023-04-03
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\glib-2.0.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'C=US, ST=California, L=Palo Alto, O=''VMware, Inc.'', OU=Digital ID Class 3 - Microsoft Software Validation v2, OU=Marketing, CN=''VMware, Inc.'''

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
