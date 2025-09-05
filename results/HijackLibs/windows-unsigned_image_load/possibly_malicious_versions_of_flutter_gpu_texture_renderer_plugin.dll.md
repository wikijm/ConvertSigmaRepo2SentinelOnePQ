```sql
// Translated content (automatically translated on 05-09-2025 01:20:33):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\flutter_gpu_texture_renderer_plugin.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of flutter_gpu_texture_renderer_plugin.dll
id: 7010853b-8907-48a3-9464-5b9ff8471033
status: experimental
description: Detects possible DLL hijacking of flutter_gpu_texture_renderer_plugin.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/rustdesk/flutter_gpu_texture_renderer_plugin.html
author: "Wietze Beukema"
date: 2025-02-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\flutter_gpu_texture_renderer_plugin.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=PURSLANE, O=PURSLANE, S=North West, C=SG, SERIALNUMBER=53481265A'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
