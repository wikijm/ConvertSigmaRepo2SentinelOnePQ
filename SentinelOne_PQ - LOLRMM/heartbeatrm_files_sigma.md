```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\HeartbeatRM\*" or tgt.file.path contains "C:\\Program Files\\HeartbeatRM\*" or tgt.file.path contains "\\agent-installer-any.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential HeartbeatRM RMM Tool File Activity
id: 6068f888-107c-5be5-a931-c7fef5f8f22b
status: experimental
description: |
    Detects potential files activity of HeartbeatRM RMM tool
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
            - 'C:\Program Files (x86)\HeartbeatRM\*'
            - 'C:\Program Files\HeartbeatRM\*'
            - '*\agent-installer-any.exe'
    condition: selection
falsepositives:
    - Legitimate use of HeartbeatRM
level: medium
```
