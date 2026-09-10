```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "RodexAgent.exe" or tgt.file.path contains "C:\\Windows\\<random-6-9-char>.exe" or tgt.file.path contains "<impersonated-org>Agent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Rodex RMM RMM Tool File Activity
id: ab98883e-9d06-5fab-937d-bf1555a872d7
status: experimental
description: |
    Detects potential files activity of Rodex RMM RMM tool
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
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'RodexAgent.exe'
            - 'C:\Windows\<random-6-9-char>.exe'
            - '<impersonated-org>Agent.exe'
    condition: selection
falsepositives:
    - Legitimate use of Rodex RMM
level: medium
```
