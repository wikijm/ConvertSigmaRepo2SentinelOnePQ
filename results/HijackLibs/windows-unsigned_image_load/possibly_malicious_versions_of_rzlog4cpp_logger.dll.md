```sql
// Translated content (automatically translated on 13-05-2025 01:27:18):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\rzlog4cpp_logger.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of rzlog4cpp_logger.dll
id: 3158223b-7740-48a3-2257-5b9ff8164996
status: experimental
description: Detects possible DLL hijacking of rzlog4cpp_logger.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/razer/rzlog4cpp_logger.html
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
        ImageLoaded: '*\rzlog4cpp_logger.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'C=US, ST=California, L=Irvine, O=Razer USA Ltd., CN=Razer USA Ltd.'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
