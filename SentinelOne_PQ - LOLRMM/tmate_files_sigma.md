```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "/tmp/tmate" or tgt.file.path contains "~/.tmate.conf" or tgt.file.path contains "tmate.sock" or tgt.file.path contains "tmate-ready" or tgt.file.path contains "tmate.bashrc"))
```


# Original Sigma Rule:
```yaml
title: Potential tmate RMM Tool File Activity
id: 968e0dd1-f6ea-55d7-9587-0c8447bb9bb2
status: experimental
description: |
    Detects potential files activity of tmate RMM tool
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
            - '/tmp/tmate*'
            - '~/.tmate.conf'
            - 'tmate.sock'
            - 'tmate-ready'
            - 'tmate.bashrc'
    condition: selection
falsepositives:
    - Legitimate use of tmate
level: medium
```
