```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "/usr/local/bin/pitunnel" or tgt.file.path contains "/etc/systemd/system/pitunnel.service"))
```


# Original Sigma Rule:
```yaml
title: Potential PiTunnel RMM Tool File Activity
id: f1e42375-f9ef-5e39-a0cf-80ed7572c8b5
status: experimental
description: |
    Detects potential files activity of PiTunnel RMM tool
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
            - '/usr/local/bin/pitunnel'
            - '/etc/systemd/system/pitunnel.service'
    condition: selection
falsepositives:
    - Legitimate use of PiTunnel
level: medium
```
