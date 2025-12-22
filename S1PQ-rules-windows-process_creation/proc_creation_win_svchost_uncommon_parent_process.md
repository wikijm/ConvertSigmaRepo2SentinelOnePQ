```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\svchost.exe" and (not ((src.process.image.path contains "\\Mrt.exe" or src.process.image.path contains "\\MsMpEng.exe" or src.process.image.path contains "\\ngen.exe" or src.process.image.path contains "\\rpcnet.exe" or src.process.image.path contains "\\services.exe" or src.process.image.path contains "\\TiWorker.exe") or not (src.process.image.path matches "\.*") or (src.process.image.path in ("-",""))))))
```


# Original Sigma Rule:
```yaml
title: Uncommon Svchost Parent Process
id: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
status: test
description: Detects an uncommon svchost parent process
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2017-08-15
modified: 2022-06-28
tags:
    - attack.defense-evasion
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
    filter_main_generic:
        ParentImage|endswith:
            - '\Mrt.exe'
            - '\MsMpEng.exe'
            - '\ngen.exe'
            - '\rpcnet.exe'
            - '\services.exe'
            - '\TiWorker.exe'
    filter_main_parent_null:
        ParentImage: null
    filter_main_parent_empty:
        ParentImage:
            - '-'
            - ''
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
