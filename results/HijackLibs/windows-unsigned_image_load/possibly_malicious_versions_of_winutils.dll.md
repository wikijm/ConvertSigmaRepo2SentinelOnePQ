```sql
// Translated content (automatically translated on 29-11-2025 01:25:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\winutils.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of winutils.dll
id: 8665403b-4150-48a3-8413-5b9ff8744995
status: experimental
description: Detects possible DLL hijacking of winutils.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/paloalto/winutils.html
author: "Wietze Beukema"
date: 2023-04-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\winutils.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'C=NL, ST=Noord-Holland, L=Amsterdam, O=Palo Alto Networks (Netherlands) B.V., OU=Palo Alto Networks, CN=Palo Alto Networks (Netherlands) B.V.'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
