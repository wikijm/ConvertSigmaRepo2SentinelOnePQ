```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "loclx.exe" or tgt.file.path contains "%APPDATA%\\loclx\\config.yaml" or tgt.file.path contains "~/.loclx/config.yaml"))
```


# Original Sigma Rule:
```yaml
title: Potential LocalXpose RMM Tool File Activity
id: b87c5358-c728-593f-bf67-7d3229c91564
status: experimental
description: |
    Detects potential files activity of LocalXpose RMM tool
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
            - 'loclx.exe'
            - '%APPDATA%\loclx\config.yaml'
            - '~/.loclx/config.yaml'
    condition: selection
falsepositives:
    - Legitimate use of LocalXpose
level: medium
```
