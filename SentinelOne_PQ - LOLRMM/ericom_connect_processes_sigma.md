```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*EricomConnectRemoteHost*.exe" or src.process.image.path contains "ericomconnnectconfigurationtool.exe") or (tgt.process.image.path="*EricomConnectRemoteHost*.exe" or tgt.process.image.path contains "ericomconnnectconfigurationtool.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Ericom Connect RMM Tool Process Activity
id: cf91f3b2-c602-46db-a818-561fb133d981
status: experimental
description: |
    Detects potential processes activity of Ericom Connect RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - EricomConnectRemoteHost*.exe
            - ericomconnnectconfigurationtool.exe
    selection_image:
        Image|endswith:
            - EricomConnectRemoteHost*.exe
            - ericomconnnectconfigurationtool.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Ericom Connect
level: medium
```
