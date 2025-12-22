```sql
// Translated content (automatically translated on 22-12-2025 00:55:34):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\wwwroot\\" or tgt.process.image.path contains "\\wmpub\\" or tgt.process.image.path contains "\\htdocs\\") and (not ((tgt.process.image.path contains "bin\\" or tgt.process.image.path contains "\\Tools\\" or tgt.process.image.path contains "\\SMSComponent\\") and src.process.image.path contains "\\services.exe"))))
```


# Original Sigma Rule:
```yaml
title: Execution From Webserver Root Folder
id: 35efb964-e6a5-47ad-bbcd-19661854018d
status: test
description: |
    Detects a program executing from a web server root folder. Use this rule to hunt for potential interesting activity such as webshell or backdoors
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2019-01-16
modified: 2024-01-18
tags:
    - attack.persistence
    - attack.t1505.003
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\wwwroot\'
            - '\wmpub\'
            - '\htdocs\'
    filter_main_generic:
        Image|contains:
            - 'bin\'
            - '\Tools\'
            - '\SMSComponent\'
        ParentImage|endswith: '\services.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Various applications
    - Tools that include ping or nslookup command invocations
level: medium
```
