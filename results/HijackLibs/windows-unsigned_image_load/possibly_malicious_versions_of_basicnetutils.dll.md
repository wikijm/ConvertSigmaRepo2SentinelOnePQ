```sql
// Translated content (automatically translated on 22-07-2025 01:44:28):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\basicnetutils.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of basicnetutils.dll
id: 8230313b-8028-48a3-7945-5b9ff8500209
status: experimental
description: Detects possible DLL hijacking of basicnetutils.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/baidu/basicnetutils.html
author: "Wietze Beukema"
date: 2023-05-03
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\basicnetutils.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'C=CN, ST=Beijing, L=Beijing, O=''Beijing Baidu Netcom Science and Technology Co.,Ltd'', OU=BPIT, CN=''Beijing Baidu Netcom Science and Technology Co.,Ltd'''

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
