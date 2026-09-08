```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\remoting_host.exe" or tgt.process.image.path contains "\\remoting_host.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Chrome Remote Desktop RMM Tool Process Activity
id: bc915205-3ead-4c5b-9cfc-5858b9370aeb
status: experimental
description: |
    Detects potential processes activity of Chrome Remote Desktop RMM tool
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
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\\remoting_host.exe'
    selection_image:
        Image|endswith: '\\remoting_host.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Chrome Remote Desktop
level: medium
```
