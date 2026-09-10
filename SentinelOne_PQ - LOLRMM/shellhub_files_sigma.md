```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "/usr/local/bin/shellhub-agent" or tgt.file.path contains "/etc/shellhub-agent/agent.env" or tgt.file.path contains "/etc/systemd/system/shellhub-agent.service"))
```


# Original Sigma Rule:
```yaml
title: Potential ShellHub RMM Tool File Activity
id: 043f520b-aea8-5ec0-990c-11c5cf828dc0
status: experimental
description: |
    Detects potential files activity of ShellHub RMM tool
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
            - '/usr/local/bin/shellhub-agent'
            - '/etc/shellhub-agent/agent.env'
            - '/etc/systemd/system/shellhub-agent.service'
    condition: selection
falsepositives:
    - Legitimate use of ShellHub
level: medium
```
