```sql
// Translated content (automatically translated on 02-08-2025 01:41:33):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\wxmsw313u_aui_vc_custom.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of wxmsw313u_aui_vc_custom.dll
id: 7670463b-9675-48a3-8026-5b9ff8778295
status: experimental
description: Detects possible DLL hijacking of wxmsw313u_aui_vc_custom.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/3rd_party/wxwidgets/wxmsw313u_aui_vc_custom.html
author: "Jai Minton"
date: 2025-05-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wxmsw313u_aui_vc_custom.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=Musecy SM ltd.,O=Musecy SM ltd.,S=Lemesos, C=CY'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
