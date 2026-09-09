```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\ProgramData\\Getscreen.me\\<date>.log" or tgt.file.path contains "C:\\ProgramData\\Getscreen.me\\<date>.gui.log" or tgt.file.path contains "C:\\ProgramData\\Getscreen.me\\session.inf" or tgt.file.path contains "C:\\Users\*\\AppData\\Local\\Getscreen.me"))
```


# Original Sigma Rule:
```yaml
title: Potential GetScreen RMM Tool File Activity
id: 52b0966c-c7e5-5475-ac30-55d0f0cbdac7
status: experimental
description: |
    Detects potential files activity of GetScreen RMM tool
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
            - 'C:\ProgramData\Getscreen.me\<date>.log'
            - 'C:\ProgramData\Getscreen.me\<date>.gui.log'
            - 'C:\ProgramData\Getscreen.me\session.inf'
            - 'C:\Users\*\AppData\Local\Getscreen.me'
    condition: selection
falsepositives:
    - Legitimate use of GetScreen
level: medium
```
