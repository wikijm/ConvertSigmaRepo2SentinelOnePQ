```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\Miradore\\OnlineClient\\bin\*" or tgt.file.path contains "C:\\Program Files\\Miradore\\OnlineClient\\bin\\7z.dll"))
```


# Original Sigma Rule:
```yaml
title: Potential Miradore RMM Tool File Activity
id: 0c9a40bc-ba73-56f9-bca4-12d7c4511675
status: experimental
description: |
    Detects potential files activity of Miradore RMM tool
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
            - 'C:\Program Files\Miradore\OnlineClient\bin\*'
            - 'C:\Program Files\Miradore\OnlineClient\bin\7z.dll'
    condition: selection
falsepositives:
    - Legitimate use of Miradore
level: medium
```
