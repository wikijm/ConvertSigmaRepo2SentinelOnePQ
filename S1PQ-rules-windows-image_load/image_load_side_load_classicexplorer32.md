```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\ClassicExplorer32.dll" and (not module.path contains "C:\\Program Files\\Classic Shell\\")))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Via ClassicExplorer32.dll
id: caa02837-f659-466f-bca6-48bde2826ab4
status: test
description: Detects potential DLL sideloading using ClassicExplorer32.dll from the Classic Shell software
references:
    - https://blogs.blackberry.com/en/2022/12/mustang-panda-uses-the-russian-ukrainian-war-to-attack-europe-and-asia-pacific-targets
    - https://app.any.run/tasks/6d8cabb0-dcda-44b6-8050-28d6ce281687/
author: frack113
date: 2022-12-13
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection_classicexplorer:
        ImageLoaded|endswith: '\ClassicExplorer32.dll'
    filter_classicexplorer:
        ImageLoaded|startswith: 'C:\Program Files\Classic Shell\'
    condition: selection_classicexplorer and not filter_classicexplorer
falsepositives:
    - Unknown
level: medium
```
