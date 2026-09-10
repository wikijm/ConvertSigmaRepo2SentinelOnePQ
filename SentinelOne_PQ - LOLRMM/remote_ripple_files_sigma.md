```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "%APPDATA%\\GlavSoft\\RemoteRipple\*" or tgt.file.path contains "%TEMP%\\Remote_Ripple_"))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Ripple RMM Tool File Activity
id: 34cea967-8327-5908-9e21-15cbd18a8be5
status: experimental
description: |
    Detects potential files activity of Remote Ripple RMM tool
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
            - '%APPDATA%\GlavSoft\RemoteRipple\*'
            - '%TEMP%\Remote_Ripple_*'
    condition: selection
falsepositives:
    - Legitimate use of Remote Ripple
level: medium
```
