```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Level\\level.exe" or tgt.file.path contains "C:\\Program Files\\Level\\osqueryi.exe" or tgt.file.path contains "C:\\Program Files\\Level\\level.log"))
```


# Original Sigma Rule:
```yaml
title: Potential Level RMM Tool File Activity
id: df5537e8-61cf-45b6-8b07-0add771dd9d9
status: experimental
description: |
    Detects potential files activity of Level RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - C:\Program Files\Level\level.exe
            - C:\Program Files\Level\osqueryi.exe
            - C:\Program Files\Level\level.log
    condition: selection
falsepositives:
    - Legitimate use of Level
level: medium
```
