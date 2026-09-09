```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\veyon-wcli.exe" or src.process.image.path contains "\\veyon-worker.exe" or src.process.image.path contains "\\veyon-server.exe" or src.process.image.path contains "\\veyon-service.exe" or src.process.image.path contains "\\veyon-master.exe") or (tgt.process.image.path contains "\\veyon-wcli.exe" or tgt.process.image.path contains "\\veyon-worker.exe" or tgt.process.image.path contains "\\veyon-server.exe" or tgt.process.image.path contains "\\veyon-service.exe" or tgt.process.image.path contains "\\veyon-master.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Veyon RMM Tool Process Activity
id: 14567547-1ca1-5c54-b074-422ba9d11087
status: experimental
description: |
    Detects potential processes activity of Veyon RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\veyon-wcli.exe'
            - '\\veyon-worker.exe'
            - '\\veyon-server.exe'
            - '\\veyon-service.exe'
            - '\\veyon-master.exe'
    selection_image:
        Image|endswith:
            - '\\veyon-wcli.exe'
            - '\\veyon-worker.exe'
            - '\\veyon-server.exe'
            - '\\veyon-service.exe'
            - '\\veyon-master.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Veyon
level: medium
```
