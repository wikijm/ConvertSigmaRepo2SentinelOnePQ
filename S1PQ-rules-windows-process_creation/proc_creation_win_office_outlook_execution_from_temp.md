```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\\Temporary Internet Files\\Content.Outlook\\")
```


# Original Sigma Rule:
```yaml
title: Suspicious Execution From Outlook Temporary Folder
id: a018fdc3-46a3-44e5-9afb-2cd4af1d4b39
status: test
description: Detects a suspicious program execution in Outlook temp folder
author: Florian Roth (Nextron Systems)
references:
    - Internal Research
date: 2019-10-01
modified: 2022-10-09
tags:
    - attack.initial-access
    - attack.t1566.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\Temporary Internet Files\Content.Outlook\'
    condition: selection
falsepositives:
    - Unknown
level: high
```
