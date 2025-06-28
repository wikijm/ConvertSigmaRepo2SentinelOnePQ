```sql
// Translated content (automatically translated on 28-06-2025 01:27:13):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\windowsperformancerecorderui.dll" and (not (not (module.path matches "\.*") or not (module.path matches "\.*") or not (module.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Possibly malicious versions of windowsperformancerecorderui.dll
id: 1067753b-2811-48a3-1599-5b9ff8544858
status: experimental
description: Detects possible DLL hijacking of windowsperformancerecorderui.dll by looking for versions not meeting the known signature data.
references:
    - https://hijacklibs.net/entries/microsoft/external/windowsperformancerecorderui.html
author: "Gary Lobermier"
date: 2023-05-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\windowsperformancerecorderui.dll'
    filter:
        ImageLoaded:
            - Signed: 'true'
            - SignatureStatus: 'signed'
            - Signature|contains:
                - 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.
```
