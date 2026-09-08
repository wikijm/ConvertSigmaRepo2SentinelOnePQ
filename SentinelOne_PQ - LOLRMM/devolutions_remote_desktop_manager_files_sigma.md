```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "%localappdata%\\Devolutions\\RemoteDesktopManager\\Connections.log" or tgt.file.path contains "%localappdata%\\Devolutions\\RemoteDesktopManager[GUID]\\Mru.xml" or tgt.file.path contains "%localappdata%\\Devolutions\\RemoteDesktopManager\\Connections.db"))
```


# Original Sigma Rule:
```yaml
title: Potential Devolutions Remote Desktop Manager RMM Tool File Activity
id: 19ed3ecc-024f-4afe-bc9c-5c61e581846f
status: experimental
description: |
    Detects potential files activity of Devolutions Remote Desktop Manager RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
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
            - '%localappdata%\Devolutions\RemoteDesktopManager\Connections.log'
            - '%localappdata%\Devolutions\RemoteDesktopManager[GUID]\Mru.xml'
            - '%localappdata%\Devolutions\RemoteDesktopManager\Connections.db'
    condition: selection
falsepositives:
    - Legitimate use of Devolutions Remote Desktop Manager
level: medium
```
